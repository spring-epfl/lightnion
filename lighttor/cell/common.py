from . import view as _view

class length_halved_view(_view.cache(_view.uint)):
    def cache(self):
        return super().cache() // 2

    def iseven(self):
        return bool(self._cache.value % 2 == 0)

    def write(self, payload=b'', value=None):
        return super().write(payload, value * 2)

    def valid(self, payload=b''):
        if not super().valid(payload):
            return False
        return self.value(payload) > 0 and self.cached() and self.iseven()
