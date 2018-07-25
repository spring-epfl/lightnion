import collections
import threading
import ipaddress
import inspect
import codecs
import enum as _enum

class basic:
    def width(self, payload=b''):
        raise NotImplementedError

    def valid(self, payload=b''):
        raise NotImplementedError

    def value(self, payload=b'', field=None):
        raise NotImplementedError

    def write(self, payload=b'', value=None, **kwargs):
        raise NotImplementedError

    def __contains__(self, field):
        return False

class composite(basic):
    def write(self, payload=b'', value=None, **kwargs):
        raise NotImplementedError

    def __len__(self):
        raise NotImplementedError

    def __contains__(self, field):
        raise NotImplementedError

    def __getitem__(self, field):
        raise NotImplementedError

class uint(basic):
    def __init__(self, size, byteorder='big'):
        if size < 1:
            raise ValueError('Invalid uint size: {}'.format(size))
        if byteorder not in ['big', 'little']:
            raise ValueError('Invalid uint byteorder: {}'.format(byteorder))
        self.byteorder = byteorder
        self.size = size

    def width(self, payload=b''):
        return self.size

    def valid(self, payload=b''):
        return len(payload) >= self.size

    def value(self, payload=b'', field=None):
        return int.from_bytes(payload[:self.size], byteorder=self.byteorder)

    def write(self, payload=b'', value=None, **kwargs):
        value = int(value).to_bytes(self.size, byteorder=self.byteorder)
        return value + payload[self.size:]

def enum(size, byteorder='big', typename=None, cached=False):
    if typename is not None and not typename.isidentifier():
        raise ValueError('Typename {} is not an identifier'.format(typename))

    @_enum.unique
    class _anonymous_enum(_enum.Enum):
        def __new__(cls, value):
            member = object.__new__(cls)
            member._value_ = value
            return member

        @classmethod
        def width(cls, payload=b''):
            return size

        @classmethod
        def valid(cls, payload=b''):
            if len(payload) < size:
                return False

            try:
                cls.value(payload)
                return True
            except ValueError:
                return False

        def __int__(self):
            return self._value_

        @classmethod
        def value(cls, payload=b'', field=None):
            value = int.from_bytes(payload[:size], byteorder='big')
            return cls(value)

        @classmethod
        def write(cls, payload=b'', value=None, **kwargs):
            value = int(cls(value)).to_bytes(size, byteorder='big')
            return value + payload[size:]

    if cached:
        class _anonymous_cached_enum(_anonymous_enum):
            @classmethod
            def cache(cls):
                if not cls.cached():
                    raise RuntimeError('Bounded value unknown at runtime: '
                        + 'Have you called .value() of parent view yet?')
                return cls._cache.value

            @classmethod
            def cached(cls):
                return cls._cache.value is not None

            @classmethod
            def value(cls, payload=b'', field=None):
                value = int.from_bytes(payload[:size], byteorder='big')
                cls._cache.value = cls(value)
                return cls.cache()

            @classmethod
            def write(cls, payload=b'', value=None, **kwargs):
                value = int(cls(value)).to_bytes(size, byteorder='big')
                cls._cache.value = cls.value(value)
                return value + payload[size:]

        _anonymous_cached_enum._cache = threading.local()
        _anonymous_cached_enum._cache.value = None
        _anonymous_enum = _anonymous_cached_enum

    if typename is not None:
        _anonymous_enum.__qualname__ = typename
    return _anonymous_enum

class data(basic):
    def __init__(self, size):
        if isinstance(size, int) and not size < 0:
            fixed = True
        elif isview(size) and iscached(size):
            fixed = False
        else:
            raise ValueError('Invalid size: {}'.format(size))
        self.length = size
        self.fixed = fixed

    @property
    def size(self):
        if self.fixed:
            return self.length
        return self.length.cache()

    def width(self, payload=b''):
        return self.size

    def valid(self, payload=b''):
        if not self.fixed and not self.length.cached():
            return False
        return len(payload) >= self.size

    def value(self, payload=b'', field=None):
        return payload[:self.size]

    def write(self, payload=b'', value=None, **kwargs):
        if len(value) != self.size:
            raise ValueError('Invalid value size: {} instead of {}'.format(
                len(value), self.size))
        return value + payload[self.size:]

class fields(composite):
    def __init__(self, **kwargs):
        for key, view in kwargs.items():
            if not isview(view):
                raise TypeError('Field {} is not a view: {}'.format(key, view))
        self._fields = collections.OrderedDict(kwargs)

    def visit(self, payload=b'', operator=lambda v, p: v.width(p)):
        results = []
        for _, view in self._fields.items():
            width = view.width(payload)
            results.append(operator(view, payload))
            payload = payload[width:]
        return results

    def offset(self, payload=b'', field=None):
        if field not in self:
            raise ValueError('Field {} not in fields'.format(field))

        offset = 0
        for key, view in self._fields.items():
            if key == field:
                return offset
            width = view.width(payload)
            offset += width
            payload = payload[width:]

    def width(self, payload=b''):
        return sum(self.visit(payload, lambda v, p: v.width(p)))

    def valid(self, payload=b''):
        for field, view in self._fields.items():
            if not view.valid(payload):
                return False
            width = view.width(payload)
            payload = payload[width:]
        return True

    def value(self, payload=b'', field=None):
        if field is None:
            values = self.visit(payload, lambda v, p: v.value(p))
            return {key: value
                for (key, _), value in zip(self._fields.items(), values)}

        offset = self.offset(payload, field)
        return self._fields[field].value(payload[offset:])

    def write(self, payload=b'', value=None, **kwargs):
        if len(kwargs) > 0:
            if value is not None:
                raise RuntimeError('Conflict: value and kwargs both given.')
            value = kwargs

        for field, svalue in value.items():
            offset = self.offset(payload, field)
            svalue = self._fields[field].write(payload[offset:], svalue)
            payload = payload[:offset] + svalue
        return payload

    def __len__(self):
        return len(self._fields)

    def __contains__(self, field):
        return field in self._fields

    def __getitem__(self, field):
        return self.__getattr__(field)

    def __getattr__(self, field):
        return self._fields[field]

class packet(fields):
    _max_size = 1024 * 1024
    _default_extra_fields = None
    _default_header_view = None
    _default_field_name = 'length'
    _default_fixed_size = 0
    _default_data_view = data
    _default_data_name = 'data'

    def __init__(self, header_view=None, fixed_size=None, field_name=None,
        data_name=None, data_view=None, extra_fields=None):

        if extra_fields is None:
            extra_fields = self._default_extra_fields
        if extra_fields is None:
            extra_fields = []
        if header_view is None:
            header_view = self._default_header_view
        if field_name is None:
            field_name = self._default_field_name
        if fixed_size is None:
            fixed_size = self._default_fixed_size
        if data_view is None:
            data_view = self._default_data_view
        if data_name is None:
            data_name = self._default_data_name

        if not isinstance(header_view, fields):
            raise TypeError('Header not a view.fields: {}'.format(header_view))

        self._fixed_size = True
        if field_name in header_view:
            self._fixed_size = False
            extra_fields.append(field_name)

        if inspect.isclass(data_view):
            if self._fixed_size:
                data_view = data_view(fixed_size)
            else:
                data_view = data_view(header_view._fields[field_name])

        if not isview(data_view):
            raise TypeError('Data view not a view: {}'.format(data_view))

        self._extra_fields = extra_fields
        self._field_name = field_name
        self._data_name = data_name
        super().__init__(**{'header': header_view, data_name: data_view})

    @property
    def fixed_size(self):
        return self._fixed_size

    def cache_fields(self, payload=b'', value=None):
        for field in self._extra_fields:
            self.header.value(payload, field)

    def offset(self, payload=b'', field=None):
        if field in self._fields:
            return super().offset(payload, field=field)
        return self.header.offset(payload, field=field)

    def width(self, payload=b''):
        if len(self._extra_fields) > 0:
            self.cache_fields(payload)
        return super().width(payload)

    def valid(self, payload=b''):
        if not self.header.valid(payload):
            return False
        if len(self._extra_fields) > 0:
            self.cache_fields(payload)
        if not self.fixed_size:
            width = self.header.value(payload, self._field_name)
            if width > self._max_size:
                return False
        return super().valid(payload)

    def value(self, payload=b'', field=None):
        if field == self._data_name:
            if len(self._extra_fields) > 0:
                self.cache_fields(payload)
            return super().value(payload, self._data_name)
        elif field is None:
            whole = self.header.value(payload, field=None)
            whole[self._data_name] = self.value(payload, self._data_name)
            return whole
        return self.header.value(payload, field)

    def write(self, payload=b'', value=None, **kwargs):
        if len(kwargs) > 0:
            if value is not None:
                raise RuntimeError('Conflict: value and kwargs both given.')
            value = kwargs

        if 'header' in value:
            payload = super().write(payload, header=value['header'])
            value = dict(value)
            del value['header']

        if len(self._extra_fields) > 0 and self._data_name in value:
            self.cache_fields(payload)

        if self._data_name in value:
            if len(value) > 1:
                headers = dict(value)
                del headers[self._data_name]
                payload = self.header.write(payload, headers)

            return super().write(payload,
                **{self._data_name: value[self._data_name]})

        return self.header.write(payload, value)

    def __len__(self):
        return len(self.header) + 1

    def __contains__(self, field):
        return field in self._fields or field in self.header

    def __getitem__(self, field):
        return self.__getattr__(field)

    def __getattr__(self, field):
        if field in ['header', self._data_name]:
            return self._fields[field]
        return self.header[field]

class series(composite):
    max_quantity = 32
    def __init__(self, item_view, n):
        if isinstance(n, int) and not n < 1:
            fixed = True
        elif isview(n) and iscached(n):
            fixed = False
        else:
            raise ValueError('Invalid quantity: {}'.format(n))
        self.length = n
        self.fixed = fixed
        self.item = item_view

    @property
    def quantity(self):
        if self.fixed:
            return self.length
        return self.length.cache()

    def offset(self, payload=b'', field=None):
        field = int(field)
        if not self.quantity > field:
            raise IndexError('Invalid item index: {}'.format(field))

        total_offset = 0
        for _ in range(field):
            width = self.item.width(payload)
            payload = payload[width:]
            total_offset += width
        return total_offset

    def width(self, payload=b''):
        offset = self.offset(payload, self.quantity - 1)
        return offset + self.item.width(payload[offset:])

    def valid(self, payload=b''):
        if self.quantity > self.max_quantity:
            return False

        for _ in range(self.quantity):
            if not self.item.valid(payload):
                return False
            width = self.item.width(payload)
            payload = payload[width:]
        return True

    def value(self, payload=b'', field=None):
        if field is None:
            results = []
            for _ in range(self.quantity):
                results.append(self.item.value(payload))
                width = self.item.width(payload)
                payload = payload[width:]
            return results

        field = int(field)
        if not self.quantity > field:
            raise IndexError('Invalid item index: {}'.format(field))

        return self.item.value(payload[self.offset(payload, field):])

    def write(self, payload=b'', value=None, **kwargs):
        if len(kwargs) > 0:
            if value is not None:
                raise RuntimeError('Conflict: value and kwargs both given.')
            value = kwargs

        if isinstance(value, list):
            if len(value) > self.quantity:
                raise ValueError(
                    'Input list too long: {} out of {} items'.format(
                    len(value), self.quantity))
            return self.write(payload, dict(enumerate(value)))

        if isinstance(value, tuple) and isinstance(value[0], (int, str)):
            field = int(value[0])
            offset = self.offset(payload, field)
            svalue = self.item.write(payload[offset:], value[1])
            return payload[:offset] + svalue

        for field, svalue in sorted(value.items()):
            payload = self.write(payload, value=(int(field), svalue))
        return payload

    def __len__(self):
        return self.quantity

    def __contains__(self, field):
        try:
            return int(field) < self.quantity
        except ValueError:
            return False

    def __getitem__(self, field):
        return self.item

class union(composite):
    def __init__(self, view_table, union_tag):
        for key, view in view_table.items():
            if not isview(view):
                raise TypeError('Union of {} not a view: {}'.format(key, view))

        self.view_table = view_table
        self.union_tag = union_tag

    @property
    def tag(self):
        return self.union_tag.cache()

    @property
    def active_view(self):
        return self.view_table[self.tag]

    def offset(self, payload=b'', field=None):
        return 0

    def width(self, payload=b''):
        return self.active_view.width(payload)

    def valid(self, payload=b''):
        if self.tag not in self.view_table:
            return False

        return self.active_view.valid(payload)

    def value(self, payload=b'', field=None):
        return self.active_view.value(payload, field)

    def write(self, payload=b'', value=None, **kwargs):
        return self.active_view.write(payload, value=value, **kwargs)

    def __contains__(self, field):
        return field in self.active_view

class wrapper:
    '''This is a view bound to raw bytes.

    See help(self.view) for details on the underlying view.'''

    def __init__(self, parent_view):
        if not isview(parent_view):
            raise TypeError('Wrapping not a view: {}'.format(parent_view))
        self._view = parent_view

    @property
    def raw(self):
        raise NotImplementedError

    @raw.setter
    def raw(self, value):
        raise NotImplementedError

    @property
    def width(self):
        return self._view.width(self.raw)

    @property
    def valid(self):
        return self._view.valid(self.raw)

    def offset(self, field):
        return self._view.offset(self.raw, field)

    def value(self, field=None):
        if field is None:
            return self._view.value(self.raw)
        return self._view.value(self.raw, field=field)

    def write(self, value=None, **kwargs):
        self.raw = self._view.write(self.raw, value, **kwargs)

    def truncate(self, width=None):
        if width is None:
            width = self.width
        self.raw = self.raw[:width]

    def finalize(self, truncate=True):
        if truncate:
            self.truncate()
        if not self.valid:
            raise RuntimeError('Invalid payload for {} view: {}'.format(
                self._view, self.raw))

    def set(self, *kargs, **kwargs):
        self.write(*kargs, **kwargs)
        self.finalize()

    def __len__(self):
        if not iscomposite(self._view):
            raise NotImplementedError
        return len(self._view)

    def __contains__(self, field):
        if not iscomposite(self._view):
            raise NotImplementedError
        return field in self._view

    def __getitem__(self, field):
        return self.__getattr__(str(field))

    def __setitem__(self, field, value):
        self.__setattr__(str(field), value)

    def __setattr__(self, field, value):
        if (not field.startswith('_')
            and iscomposite(self._view) and field in self._view):
            self.write(value={field: value})
        else:
            object.__setattr__(self, field, value)

    def __getattr__(self, field):
        if field == '__name__':
            return self.__class__.__name__

        if iscomposite(self._view) and field in self._view:
            subview = self._view[field]
            if iscomposite(subview):
                return bind(subview, self, field)
        return self._view.value(self.raw, field)

def _forward_init(cls, args):
    if args is None:
        return cls

    if isinstance(args, dict):
        if len(args) == 2 and 'kargs' in args and 'kwargs' in args:
            return cls(*args['kargs'], **args['kwargs'])
        if len(args) == 1 and 'kwargs' in args:
            return cls(**args['kwargs'])
        if len(args) == 1 and 'kargs' in args:
            return cls(*args['kargs'])

        return cls(**args)
    return cls(*args)

def bind(parent_view, parent_wrapper, parent_field=None, init=[]):
    class _anonymous_subwrapper(wrapper):
        def __init__(self):
            super().__init__(parent_view)
            self._parent = parent_wrapper
            self._field = parent_field

        @property
        def raw(self):
            if self._field is None:
                return self._parent.raw
            offset = self._parent.offset(self._field)
            return self._parent.raw[offset:]

        @raw.setter
        def raw(self, value):
            if self._field is None:
                self._parent.raw = value
                return
            parent = self._parent.raw
            offset = self._parent.offset(self._field)
            parent = parent[:offset] + value + parent[offset + len(value):]
            self._parent.raw = parent

    typename = str(parent_field)
    if typename is not None:
        if not typename.isidentifier():
            try:
                if int(typename) >= 0:
                    typename = 'idx_{}'.format(typename)
            except ValueError:
                pass

        if typename.isidentifier():
            _anonymous_subwrapper.__name__ = '{}'.format(typename)

    _anonymous_subwrapper.__qualname__ = '{}.{}'.format(
        parent_wrapper.__class__.__qualname__, _anonymous_subwrapper.__name__)
    return _forward_init(_anonymous_subwrapper, init)

def like(parent_view, typename=None, init=None):
    if typename is not None and not typename.isidentifier():
        raise ValueError('Typename {} is not an identifier'.format(typename))

    class _anonymous_wrapper(wrapper):
        def __init__(self, raw):
            super().__init__(parent_view)
            self._raw = raw

        @property
        def raw(self):
            return self._raw

        @raw.setter
        def raw(self, value):
            self._raw = value

    if typename is not None:
        _anonymous_wrapper.__qualname__ = 'wrapper.{}'.format(typename)
        _anonymous_wrapper.__name__ = '{}_wrapper'.format(typename)

    return _forward_init(_anonymous_wrapper, init)

def cache(base, typename=None, init=None):
    if typename is not None and not typename.isidentifier():
        raise ValueError('Typename {} is not an identifier'.format(typename))

    if not inspect.isclass(base):
        raise TypeError('Expect a class: {} is not.'.format(base))

    if issubclass(base, _enum.Enum):
        raise TypeError('Use view.enum(cached=True) to cache enumerations.')

    if iscached(base):
        raise TypeError('Class {} already cached.'.format(base))

    class _anonymous_cached_view(base):
        def __init__(self, *kargs, **kwargs):
            '''See help({}.__init__) for an accurate signature.'''.format(
                base.__qualname__)

            base.__init__(self, *kargs, **kwargs)
            self._cache = threading.local()
            self._cache.value = None

        def cache(self):
            if not self.cached():
                raise RuntimeError('Bounded value unknown at runtime: '
                    + 'Have you called .value() of parent view yet?')
            return self._cache.value

        def cached(self):
            return self._cache.value is not None

        def value(self, payload=b'', field=None):
            self._cache.value = super().value(payload)
            return self.cache()

        def write(self, payload=b'', *kargs, **kwargs):
            payload = super().write(payload, *kargs, **kwargs)
            self._cache.value = self.value(payload)
            return payload

    _anonymous_cached_view.__qualname__ = 'cached.{}'.format(base.__name__)
    _anonymous_cached_view.__name__ = 'cached_{}'.format(base.__name__)
    if typename is not None:
        _anonymous_cached_view.__name__ = typename

    return _forward_init(_anonymous_cached_view, init)

def isview(item):
    if not hasattr(item, 'width') or not inspect.ismethod(item.width):
        return False
    if not hasattr(item, 'valid') or not inspect.ismethod(item.valid):
        return False
    if not hasattr(item, 'value') or not inspect.ismethod(item.value):
        return False
    if not hasattr(item, 'write') or not inspect.ismethod(item.write):
        return False
    return True

def iscached(item):
    if not hasattr(item, 'cache') or not inspect.ismethod(item.cache):
        return False
    if not hasattr(item, 'cached') or not inspect.ismethod(item.cache):
        return False
    return True

def iscomposite(item):
    if isinstance(item, union):
        if not item.union_tag.cached():
            return True
        return isinstance(item.active_view, composite)
    return isinstance(item, composite)

class ip_address(data):
    def __init__(self, *, version):
        if version not in [4, 6]:
            raise ValueError('Invalid IP version: {}'.format(version))

        if version == 4:
            self._ip_type = ipaddress.IPv4Address
            super().__init__(4)
        else:
            self._ip_type = ipaddress.IPv6Address
            super().__init__(16)

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        try:
            self.value(payload)
            return True
        except ipaddress.AddressValueError:
            return False

    def value(self, payload=b'', field=None):
        value = super().value(payload)
        return self._ip_type(value)

    def write(self, payload=b'', value=None, **kwargs):
        if not isinstance(value, self._ip_type):
            value = self._ip_type(value)
        return super().write(payload, value=value.packed)

class codec(data):
    @staticmethod
    def _is_text_encoding(c):
        try:
            codecs.encode(b'', c)
            return False
        except BaseException:
            pass

        try:
            if not isinstance(codecs.encode('', c), bytes):
                return False
            return True
        except BaseException:
            return False

    @staticmethod
    def _is_bytes_mapping(c):
        if codec._is_text_encoding(c):
            return False

        try:
            if not isinstance(codecs.encode(b'', c), bytes):
                return False
            return True
        except BaseException:
            return False

    @staticmethod
    def _is_text_mapping(c):
        return c in ['rot_13', 'rot13']

    @staticmethod
    def _build_encode_chain(codecs):
        encode_chain = []
        is_input_str = True
        for c in codecs:
            if codec._is_text_encoding(c):
                encode_chain.append((is_input_str, c))
                is_input_str = bool(not is_input_str)
                continue
            if codec._is_text_encoding(c) and not is_input_str:
                raise ValueError(
                    'Got bytes for {} in chain: {}'.format(c, codecs))
            if codec._is_bytes_mapping(c) and is_input_str:
                raise ValueError(
                    'Got str for {} in chain: {}'.format(c, codecs))
            encode_chain.append((True, c))

        if is_input_str:
            raise ValueError(
                'Chain encodes to str instead of bytes: {}'.format(codecs))
        return encode_chain

    @staticmethod
    def _build_decode_chain(codecs):
        decode_chain = []
        is_input_str = False
        for c in reversed(codecs):
            if codec._is_text_encoding(c):
                decode_chain.append((is_input_str, c))
                is_input_str = bool(not is_input_str)
                continue
            if codec._is_text_encoding(c) and not is_input_str:
                raise ValueError(
                    'Got bytes for {} in chain: {}'.format(c, codecs))
            if codec._is_bytes_mapping(c) and is_input_str:
                raise ValueError(
                    'Got str for {} in chain: {}'.format(c, codecs))
            decode_chain.append((False, c))

        if not is_input_str:
            raise ValueError(
                'Chain decodes to bytes instead of str: {}'.format(codecs))
        return decode_chain

    def __init__(self, *codecs, size):
        self.encode_chain = codec._build_encode_chain(codecs)
        self.decode_chain = codec._build_decode_chain(codecs)
        super().__init__(size)

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False

        try:
            self.value(payload)
            return True
        except ValueError:
            return False

    def value(self, payload=b'', field=None):
        value = super().value(payload)
        for use_encode, c in self.decode_chain:
            if use_encode:
                value = codecs.encode(value, c)
            else:
                value = codecs.decode(value, c)
        return value

    def write(self, payload=b'', value=None, **kwargs):
        for use_encode, c in self.encode_chain:
            if use_encode:
                value = codecs.encode(value, c)
            else:
                value = codecs.decode(value, c)
        return super().write(payload, value=value)
