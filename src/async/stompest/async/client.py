"""The asynchronous client is based on `Twisted <http://twistedmatrix.com/>`_, a very mature and powerful asynchronous programming framework. It supports destination specific message and error handlers (with default "poison pill" error handling), concurrent message processing, graceful shutdown, and connect and disconnect timeouts.

.. seealso:: `STOMP protocol specification <http://stomp.github.com/>`_, `Twisted API documentation <http://twistedmatrix.com/documents/current/api/>`_, `Apache ActiveMQ - Stomp <http://activemq.apache.org/stomp.html>`_

Examples
--------

.. automodule:: stompest.async.examples
    :members:

Producer
^^^^^^^^

.. literalinclude:: ../../src/async/stompest/async/examples/producer.py

Transformer
^^^^^^^^^^^

.. literalinclude:: ../../src/async/stompest/async/examples/transformer.py

Consumer
^^^^^^^^

.. literalinclude:: ../../src/async/stompest/async/examples/consumer.py

API
---
"""
import logging

from twisted.internet import defer, task

from stompest.error import StompConnectionError, StompFrameError
from stompest.protocol import StompSession, StompSpec
from stompest.util import checkattr

from .listener import ConnectListener, DisconnectListener
from .protocol import StompProtocolCreator
from .util import exclusive

LOG_CATEGORY = __name__

connected = checkattr('_protocol')

class Stomp(object):
    """An asynchronous STOMP client for the Twisted framework.

    :param config: A :class:`~.StompConfig` object.
    
    .. note :: All API methods which may request a **RECEIPT** frame from the broker -- which is indicated by the **receipt** parameter -- will wait for the **RECEIPT** response until this client's **receiptTimeout**. Here, "wait" is to be understood in the asynchronous sense that the method's :class:`twisted.internet.defer.Deferred` result will only call back then. If **receipt** is :obj:`None`, no such header is sent, and the callback will be triggered earlier.

    .. seealso :: :class:`~.StompConfig` for how to set configuration options, :class:`~.StompSession` for session state, :mod:`.protocol.commands` for all API options which are documented here.
    """
    _protocolCreatorFactory = StompProtocolCreator

    def __init__(self, config):
        self._config = config

        self._session = StompSession(self._config.version, self._config.check)
        self._protocol = None
        self._protocolCreator = self._protocolCreatorFactory(self._config.uri)

        self.log = logging.getLogger(LOG_CATEGORY)

        self._disconnecting = False

        self._handlers = {
            'MESSAGE': self._onMessage,
            'CONNECTED': self._onConnected,
            'ERROR': self._onError,
            'RECEIPT': self._onReceipt,
        }

        self._listeners = []

    def add(self, listener):
        if listener not in self._listeners:
            self._listeners.append(listener)

    def remove(self, listener):
        self._listeners.remove(listener)

    @property
    def disconnected(self):
        """This :class:`twisted.internet.defer.Deferred` calls back when the connection to the broker was lost. It will err back when the connection loss was unexpected or caused by another error.
        """
        return self._disconnected

    @property
    def session(self):
        """The :class:`~.StompSession` associated to this client.
        """
        return self._session

    def sendFrame(self, frame):
        """Send a raw STOMP frame.

        .. note :: If we are not connected, this method, and all other API commands for sending STOMP frames except :meth:`~.async.client.Stomp.connect`, will raise a :class:`~.StompConnectionError`. Use this command only if you have to bypass the :class:`~.StompSession` logic and you know what you're doing!
        """
        self._protocol.send(frame)
        return self._notify(lambda l: l.onSend(self, frame))

    #
    # STOMP commands
    #
    @exclusive
    @defer.inlineCallbacks
    def connect(self, headers=None, versions=None, host=None, heartBeats=None, connectTimeout=None, connectedTimeout=None):
        """connect(headers=None, versions=None, host=None, heartBeats=None, connectTimeout=None, connectedTimeout=None)

        Establish a connection to a STOMP broker. If the wire-level connect fails, attempt a failover according to the settings in the client's :class:`~.StompConfig` object. If there are active subscriptions in the :attr:`~.async.client.Stomp.session`, replay them when the STOMP connection is established. This method returns a :class:`twisted.internet.defer.Deferred` object which calls back with :obj:`self` when the STOMP connection has been established and all subscriptions (if any) were replayed. In case of an error, it will err back with the reason of the failure.

        :param versions: The STOMP protocol versions we wish to support. The default behavior (:obj:`None`) is the same as for the :func:`~.commands.connect` function of the commands API, but the highest supported version will be the one you specified in the :class:`~.StompConfig` object. The version which is valid for the connection about to be initiated will be stored in the :attr:`~.async.client.Stomp.session`.
        :param connectTimeout: This is the time (in seconds) to wait for the wire-level connection to be established. If :obj:`None`, we will wait indefinitely.
        :param connectedTimeout: This is the time (in seconds) to wait for the STOMP connection to be established (that is, the broker's **CONNECTED** frame to arrive). If :obj:`None`, we will wait indefinitely.

        .. note :: Only one connect attempt may be pending at a time. Any other attempt will result in a :class:`~.StompAlreadyRunningError`.

        .. seealso :: The :mod:`.protocol.failover` and :mod:`~.protocol.session` modules for the details of subscription replay and failover transport.
        """
        frame = self.session.connect(self._config.login, self._config.passcode, headers, versions, host, heartBeats)

        try:
            self._protocol
        except:
            pass
        else:
            raise StompConnectionError('Already connected')

        try:
            self._protocol = yield self._protocolCreator.connect(connectTimeout, self._onFrame, self._onConnectionLost)
        except Exception as e:
            self.log.error('Endpoint connect failed')
            raise

        # disconnect listener must be added first (it must handle disconnect reasons)
        self.add(DisconnectListener()) # TODO: pass DisconnectListener parameter to self.connect()
        self.add(ConnectListener(connectedTimeout)) # TODO: pass ConnectListener parameter to self.connect()
        try:
            self.sendFrame(frame)
            yield self._notify(lambda l: l.onConnect(self, frame)) # TODO: split up in onConnecting and onConnect

        except Exception as e:
            yield self.disconnect(failure=e)
            yield self.disconnected

        self._replay()

        defer.returnValue(self)

    @connected
    @defer.inlineCallbacks
    def disconnect(self, receipt=None, failure=None, timeout=None):
        """disconnect(self, receipt=None, failure=None, timeout=None)
        
        Send a **DISCONNECT** frame and terminate the STOMP connection.

        :param failure: A disconnect reason (a :class:`Exception`) to err back. Example: ``versions=['1.0', '1.1']``
        :param timeout: This is the time (in seconds) to wait for a graceful disconnect, that is, for pending message handlers to complete. If receipt is :obj:`None`, we will wait indefinitely.

        .. note :: The :attr:`~.async.client.Stomp.session`'s active subscriptions will be cleared if no failure has been passed to this method. This allows you to replay the subscriptions upon reconnect. If you do not wish to do so, you have to clear the subscriptions yourself by calling the :meth:`~.StompSession.close` method of the :attr:`~.async.client.Stomp.session`. The result of any (user-requested or not) disconnect event is available via the :attr:`disconnected` property.
        """
        try:
            yield self._notify(lambda l: l.onDisconnect(self, failure, timeout))
        except Exception as e:
            self.disconnect(failure=e)

        protocol = self._protocol
        try:
            if (self.session.state == self.session.CONNECTED):
                yield self.sendFrame(self.session.disconnect(receipt))
        except Exception as e:
            self.disconnect(failure=e)
        finally:
            protocol.loseConnection()

    @connected
    def send(self, destination, body='', headers=None, receipt=None):
        """send(destination, body='', headers=None, receipt=None)

        Send a **SEND** frame.
        """
        frame = self.session.send(destination, body, headers, receipt)
        return self.sendFrame(frame)

    @connected
    def ack(self, frame, receipt=None):
        """ack(frame, receipt=None)

        Send an **ACK** frame for a received **MESSAGE** frame.
        """
        frame = self.session.ack(frame, receipt)
        return self.sendFrame(frame)

    @connected
    def nack(self, frame, receipt=None):
        """nack(frame, receipt=None)

        Send a **NACK** frame for a received **MESSAGE** frame.
        """
        frame = self.session.nack(frame, receipt)
        return self.sendFrame(frame)

    @connected
    def begin(self, transaction=None, receipt=None):
        """begin(transaction=None, receipt=None)

        Send a **BEGIN** frame to begin a STOMP transaction.
        """
        frame = self.session.begin(transaction, receipt)
        return self.sendFrame(frame)

    @connected
    def abort(self, transaction=None, receipt=None):
        """abort(transaction=None, receipt=None)

        Send an **ABORT** frame to abort a STOMP transaction.
        """
        frame = self.session.abort(transaction, receipt)
        return self.sendFrame(frame)

    @connected
    def commit(self, transaction=None, receipt=None):
        """commit(transaction=None, receipt=None)

        Send a **COMMIT** frame to commit a STOMP transaction.
        """
        frame = self.session.commit(transaction, receipt)
        return self.sendFrame(frame)

    @connected
    @defer.inlineCallbacks
    def subscribe(self, destination, headers=None, receipt=None, listener=None):
        """subscribe(destination, headers=None, receipt=None, listener=None)

        :param listener: An optional :class:`~.Listener` object which will be added to this connection to handle events associated to this subscription.
        
        Send a **SUBSCRIBE** frame to subscribe to a STOMP destination. This method returns a :class:`twisted.internet.defer.Deferred` object which will fire with a token when a possibly requested **RECEIPT** frame has arrived. The callback value is a token which is used internally to match incoming **MESSAGE** frames and must be kept if you wish to :meth:`~.async.client.Stomp.unsubscribe` later.
        """
        frame, token = self.session.subscribe(destination, headers, receipt, listener)
        if listener:
            self.add(listener)
        yield self._notify(lambda l: l.onSubscribe(self, frame, l))
        yield self.sendFrame(frame)
        defer.returnValue(token)

    @connected
    @defer.inlineCallbacks
    def unsubscribe(self, token, receipt=None):
        """unsubscribe(token, receipt=None)

        Send an **UNSUBSCRIBE** frame to terminate an existing subscription.

        :param token: The result of the :meth:`~.async.client.Stomp.subscribe` command which initiated the subscription in question.
        """
        context = self.session.subscription(token)
        frame = self.session.unsubscribe(token, receipt)
        yield self.sendFrame(frame)
        yield self._notify(lambda l: l.onUnsubscribe(self, frame, context))

    #
    # callbacks for received STOMP frames
    #
    @defer.inlineCallbacks
    def _onFrame(self, frame):
        yield self._notify(lambda l: l.onFrame(self, frame))
        if not frame:
            return
        try:
            handler = self._handlers[frame.command]
        except KeyError:
            raise StompFrameError('Unknown STOMP command: %s' % repr(frame))
        yield handler(frame)

    def _onConnected(self, frame):
        self.session.connected(frame)
        self.log.info('Connected to stomp broker [session=%s, version=%s]' % (self.session.id, self.session.version))
        self._protocol.setVersion(self.session.version)
        return self._notify(lambda l: l.onConnected(self, frame))

    def _onError(self, frame):
        return self._notify(lambda l: l.onError(self, frame))

    @defer.inlineCallbacks
    def _onMessage(self, frame):
        headers = frame.headers
        messageId = headers[StompSpec.MESSAGE_ID_HEADER]

        try:
            token = self.session.message(frame)
        except:
            self.log.error('Ignoring message (no handler found): %s [%s]' % (messageId, frame.info()))
            defer.returnValue(None)
        context = self.session.subscription(token)

        try:
            yield self._notify(lambda l: l.onMessage(self, frame, context))
        except Exception as e:
            self.log.error('Disconnecting (error in message handler): %s [%s]' % (messageId, frame.info()))
            self.disconnect(failure=e)

    def _onReceipt(self, frame):
        receipt = self.session.receipt(frame)
        return self._notify(lambda l: l.onReceipt(self, frame, receipt))

    #
    # private properties
    #
    @property
    def _protocol(self):
        protocol = self.__protocol
        if not protocol:
            raise StompConnectionError('Not connected')
        return protocol

    @_protocol.setter
    def _protocol(self, protocol):
        self.__protocol = protocol

    #
    # private helpers
    #

    def _notify(self, notify):
        return task.cooperate(notify(listener) for listener in list(self._listeners)).whenDone()

    @defer.inlineCallbacks
    def _onConnectionLost(self, reason):
        self._protocol = None
        try:
            yield self._notify(lambda l: l.onConnectionLost(self, reason))
        finally:
            yield self._notify(lambda l: l.onCleanup(self))

    def _replay(self):
        for (destination, headers, receipt, context) in self.session.replay():
            self.log.info('Replaying subscription: %s' % headers)
            self.subscribe(destination, headers=headers, receipt=receipt, listener=context)