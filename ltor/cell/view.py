import collections
import enum as _enum

class basic:
    def width(self, payload=b''):
        raise NotImplementedError

    def valid(self, payload=b''):
        raise NotImplementedError

    def value(self, payload=b''):
        raise NotImplementedError

    def write(self, payload=b'', value=None):
        raise NotImplementedError

class composite(basic):
    def write(self, payload=b'', value=None, **kwargs):
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

    def value(self, payload=b''):
        return int.from_bytes(payload[:self.size], byteorder=self.byteorder)

    def write(self, payload=b'', value=None):
        value = int(value).to_bytes(self.size, byteorder=self.byteorder)
        return value + payload[self.size:]

class length(uint):
    def __init__(self, size, byteorder='big'):
        super().__init__(size, byteorder=byteorder)
        self._cache = None

    @property
    def cached(self):
        return self._cache is not None

    @property
    def cache(self):
        if not self.cached:
            raise RuntimeError('Bounded length unknown at runtime')
        return self._cache

    def value(self, payload=b''):
        self._cache = super().value(payload)
        return self.cache

    def write(self, payload=b'', value=None):
        payload = super().write(payload, value)
        self._cache = self.value(payload)
        return payload

def enum(size, byteorder='big', typename=None):
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

        @classmethod
        def value(cls, payload=b''):
            value = int.from_bytes(payload[:size], byteorder='big')
            return cls(value)

        @classmethod
        def write(cls, payload=b'', value=None):
            value = int(cls(value)).to_bytes(size, byteorder='big')
            return value + payload[size:]

        def __int__(self):
            return self._value_

    if typename is not None:
        _anonymous_enum.__qualname__ = typename
    return _anonymous_enum

class data(basic):
    def __init__(self, size):
        if isinstance(size, int) and not size < 1:
            fixed = True
        elif isinstance(size, length):
            fixed = False
        else:
            raise ValueError('Invalid size: {}'.format(size))
        self.length = size
        self.fixed = fixed

    @property
    def size(self):
        if self.fixed:
            return self.length
        return self.length.cache

    def width(self, payload=b''):
        return self.size

    def valid(self, payload=b''):
        if not self.fixed and not self.length.cached:
            return False
        return len(payload) >= self.size

    def value(self, payload=b''):
        return payload[:self.size]

    def write(self, payload=b'', value=None):
        if len(value) != self.size:
            raise ValueError('Invalid value size: {} instead of {}'.format(
                len(value), self.size))
        return value + payload[self.size:]

class fields(composite):
    def __init__(self, **kwargs):
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
                raise ValueError('Conflict: value and kwargs both given.')
            value = kwargs

        for field, svalue in value.items():
            offset = self.offset(payload, field)
            svalue = self._fields[field].write(payload[offset:], svalue)
            payload = payload[:offset] + svalue
        return payload

    def __contains__(self, field):
        return field in self._fields

    def __getattr__(self, field):
        return self._fields[field]

class packet(fields):
    def __init__(self, header_view, fixed_size=0, field_name='length'):
        if not isinstance(header_view, fields):
            raise TypeError('Invalid header type: {}'.format(header_view))

        self._fixed_size = True
        if field_name in header_view:
            self._fixed_size = False

        if self._fixed_size:
            data_view = data(fixed_size)
        else:
            data_view = data(header_view._fields[field_name])

        self._field_name = field_name
        super().__init__(header=header_view, data=data_view)

    @property
    def fixed_size(self):
        return self._fixed_size

    def width(self, payload=b''):
        if not self.fixed_size:
            self.header.value(payload, self._field_name)
        return super().width(payload)

    def valid(self, payload=b''):
        if not self.header.valid(payload):
            return False
        elif not self.fixed_size:
            self.header.value(payload, self._field_name)
        return super().valid(payload)

    def value(self, payload=b'', field=None):
        if not self.fixed_size and field == 'data':
            self.header.value(payload, self._field_name)
        if field == 'data':
            return super().value(payload, 'data')
        return self.header.value(payload, field)

    def write(self, payload=b'', value=None, **kwargs):
        if len(kwargs) > 0:
            if value is not None:
                raise ValueError('Conflict: value and kwargs both given.')
            value = kwargs

        if 'header' in value:
            payload = super().write(payload, header=value['header'])
            del value['header']

        if not self.fixed_size and 'data' in value:
            self.header.value(payload, self._field_name)

        return super().write(payload, value)

class wrapper:
    def __init__(self, parent_view):
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

    def __setattr__(self, field, value):
        if not field.startswith('_') and field in self._view:
            self.write(value={field: value})
        else:
            object.__setattr__(self, field, value)

    def __getattr__(self, field):
        if field in self._view:
            subview = self._view._fields[field]
            if isinstance(subview, composite):
                subwrapper = bind(subview, self, field)
                return subwrapper()
        return self._view.value(self.raw, field)

def bind(parent_view, parent_wrapper, parent_field):
    class _anonymous_subwrapper(wrapper):
        def __init__(self):
            super().__init__(parent_view)
            self._parent = parent_wrapper
            self._field = parent_field

        @property
        def raw(self):
            offset = self._parent.offset(self._field)
            return self._parent.raw[offset:]

        @raw.setter
        def raw(self, value):
            parent = self._parent.raw
            offset = self._parent.offset(self._field)
            parent = parent[:offset] + value + parent[offset + len(value):]
            self._parent.raw = parent

    if parent_field.isidentifier():
        _anonymous_subwrapper.__name__ = '{}'.format(parent_field)

    _anonymous_subwrapper.__qualname__ = '{}.{}'.format(
        parent_wrapper.__class__.__qualname__, _anonymous_subwrapper.__name__)
    return _anonymous_subwrapper

def like(parent_view, typename=None):
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
    return _anonymous_wrapper
