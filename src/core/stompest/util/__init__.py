import copy
import functools

from six import text_type

from stompest.protocol import StompSpec

_RESERVED_HEADERS = {StompSpec.MESSAGE_ID_HEADER, StompSpec.DESTINATION_HEADER, u'timestamp', u'expires', u'priority'}

def filterReservedHeaders(headers):
    return dict((header, value) for (header, value) in headers.items() if header not in _RESERVED_HEADERS)

def checkattr(attribute):
    def _checkattr(f):
        @functools.wraps(f)
        def __checkattr(self, *args, **kwargs):
            getattr(self, attribute)
            return f(self, *args, **kwargs)
        return __checkattr
    return _checkattr

def cloneFrame(frame, persistent=None):
    frame = copy.deepcopy(frame)
    frame.unraw()
    headers = filterReservedHeaders(frame.headers)
    if persistent is not None:
        headers[u'persistent'] = text_type(bool(persistent)).lower()
    frame.headers = headers
    return frame
