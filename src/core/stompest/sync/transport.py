import errno
import select
import socket
import ssl
import time

from stompest.error import StompConnectionError
from stompest.protocol import StompParser


class StompFrameTransport(object):
    factory = StompParser

    READ_SIZE = 4096

    def __init__(self, host, port, protocol, ssl_context=None):
        """

        :param host:
        :type host: str
        :param port:
        :type port: int
        :param protocol:
        :type protocol: str
        :param ssl_context:
        :type ssl_context: ssl.SSLContext
        """
        self.host = host
        self.port = port
        self.protocol = protocol
        self.ssl_context = ssl_context

        self._socket = None
        self._parser = self.factory()

    def __str__(self):
        return '%s:%d' % (self.host, self.port)

    def canRead(self, timeout=None):
        self._check()
        if self._parser.canRead():
            return True

        startTime = time.time()
        try:
            if timeout is None:
                files, _, _ = select.select([self._socket], [], [])
            else:
                files, _, _ = select.select([self._socket], [], [], timeout)
        except select.error as (code, msg):
            if code == errno.EINTR:
                if timeout is None:
                    return self.canRead()
                else:
                    return self.canRead(max(0, timeout - (time.time() - startTime)))
            raise
        return bool(files)

    def connect(self, timeout=None):
        kwargs = {} if (timeout is None) else {'timeout': timeout}
        try:
            self._socket = socket.create_connection((self.host, self.port), **kwargs)
            if self.protocol == 'ssl':
                if self.ssl_context is None:
                    # noinspection PyUnresolvedReferences
                    self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                if ssl.HAS_SNI:
                    self._socket = self.ssl_context.wrap_socket(self._socket, server_hostname=self.host)
                else:
                    self._socket = self.ssl_context.wrap_socket(self._socket)
        except IOError as e:
            raise StompConnectionError('Could not establish connection [%s]' % e)
        self._parser.reset()

    def disconnect(self):
        try:
            self._socket and self._socket.close()
        except IOError as e:
            raise StompConnectionError('Could not close connection cleanly [%s]' % e)
        finally:
            self._socket = None

    def receive(self):
        while True:
            frame = self._parser.get()
            if frame is not None:
                return frame
            try:
                data = self._socket.recv(self.READ_SIZE)
                if not data:
                    raise StompConnectionError('No more data')
            except (IOError, StompConnectionError) as e:
                self.disconnect()
                raise StompConnectionError('Connection closed [%s]' % e)
            self._parser.add(data)

    def send(self, frame):
        self._write(str(frame))

    def setVersion(self, version):
        self._parser.version = version

    def _check(self):
        if not self._connected():
            raise StompConnectionError('Not connected')

    def _connected(self):
        return self._socket is not None

    def _write(self, data):
        self._check()
        try:
            self._socket.sendall(data)
        except IOError as e:
            raise StompConnectionError('Could not send to connection [%s]' % e)
