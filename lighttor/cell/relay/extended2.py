from ... import cell as _cell
from .. import view as _view

extended2_header_view = _view.fields(length=_view.cache(_view.uint, init=[2]))

class extended2_view(_view.packet):
    _default_header_view = extended2_header_view

view = extended2_view()
payload = _view.like(view, 'extended2_payload')
