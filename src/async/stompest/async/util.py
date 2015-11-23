import collections
import contextlib
import functools
import logging

from twisted.internet import defer, reactor, task
from twisted.internet.endpoints import TCP4ClientEndpoint

from stompest.error import StompAlreadyRunningError, StompNotRunningError
from stompest.util import cloneFrame

MESSAGE_FAILED_HEADER = 'message-failed'

log = logging.getLogger(__name__)


class InFlightOperations(collections.MutableMapping):
    def __init__(self, info):
        self._info = info
        self._waiting = {}

    def __len__(self):
        return len(self._waiting)

    def __iter__(self):
        return iter(self._waiting)

    def __getitem__(self, key):
        try:
            return self._waiting[key]
        except KeyError:
            raise StompNotRunningError('%s not in progress' % self.info(key))

    def __setitem__(self, key, value):
        if key in self:
            raise StompAlreadyRunningError('%s already in progress' % self.info(key))
        if not isinstance(value, defer.Deferred):
            raise ValueError('invalid value: %s' % value)
        self._waiting[key] = value

    def __delitem__(self, key):
        del self._waiting[key]

    @contextlib.contextmanager
    def __call__(self, key, log=None):
        self[key] = waiting = WaitingDeferred()
        info = self.info(key)
        log and log.debug('%s started.' % info)
        try:
            yield waiting
            if not waiting.called:
                waiting.callback(None)
        except Exception as e:
            log and log.error('%s failed [%s]' % (info, e))
            if not waiting.called:
                waiting.errback(e)
            raise
        finally:
            self.pop(key)
        log and log.debug('%s complete.' % info)

    def info(self, key):
        return ' '.join(map(str, filter(None, (self._info, key))))

class WaitingDeferred(defer.Deferred):
    @defer.inlineCallbacks
    def wait(self, timeout=None, fail=None):
        if timeout is not None:
            timeout = reactor.callLater(timeout, self.errback, fail)
        try:
            result = yield self
        finally:
            if timeout and not timeout.called:
                timeout.cancel()
        defer.returnValue(result)

def exclusive(f):
    @functools.wraps(f)
    def _exclusive(*args, **kwargs):
        if _exclusive.running:
            raise StompAlreadyRunningError('%s still running' % f.__name__)
        _exclusive.running = True
        task.deferLater(reactor, 0, f, *args, **kwargs).addBoth(_reload).chainDeferred(_exclusive.result)
        return _exclusive.result

    def _reload(result=None):
        _exclusive.running = False
        _exclusive.result = defer.Deferred()
        return result
    _reload()

    return _exclusive


def endpointFactory(broker, config, timeout=None):
    """

    :param timeout:
    :type timeout: int
    :param broker:
    :type broker: stompest.protocol.broker.Broker
    :param config:
    :type config: stompest.config.StompConfig
    :return:
    :rtype: twisted.internet.endpoints.TCP4ClientEndpoint | twisted.internet.endpoints.SSL4ClientEndpoint
    """
    protocol = broker['protocol'].lower()
    if protocol == 'tcp':
        return TCPClientEndpointFactory(broker, config, timeout=timeout)
    elif protocol == 'ssl':
        # As this requires pyOpenSSL, import it locally so as not to enforce the requirement when it is not needed
        from stompest.async.sslContext import SSLClientEndpointFactory
        return SSLClientEndpointFactory(broker, config, timeout=timeout)
    raise ValueError("Only tcp and ssl protocols are supported.")


def TCPClientEndpointFactory(broker, config, timeout=None):
    """

    :param broker:
    :type broker: stompest.protocol.broker.Broker
    :param config:
    :type config: stompest.config.StompConfig
    :param timeout:
    :type timeout: int
    :return:
    :rtype: twisted.internet.endpoints.TCP4ClientEndpoint
    """
    return TCP4ClientEndpoint(
        reactor,
        host=broker.host,
        port=broker.port,
        timeout=timeout
    )


def sendToErrorDestination(connection, failure, frame, errorDestination):
    """sendToErrorDestination(failure, frame, errorDestination)

    This is the default error handler for failed **MESSAGE** handlers: forward the offending frame to the error destination (if given) and ack the frame. As opposed to earlier versions, It may be used as a building block for custom error handlers.

    .. seealso :: The **onMessageFailed** argument of the :meth:`~.async.client.Stomp.subscribe` method.
    """
    if not errorDestination:
        return
    errorFrame = cloneFrame(frame, persistent=True)
    errorFrame.headers.setdefault(MESSAGE_FAILED_HEADER, str(failure))
    connection.send(errorDestination, errorFrame.body, errorFrame.headers)

def sendToErrorDestinationAndRaise(client, failure, frame, errorDestination):
    sendToErrorDestination(client, failure, frame, errorDestination)
    raise failure
