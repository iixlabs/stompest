import re


class Broker(object):
    _REGEX_URI = re.compile('^(?P<protocol>tcp|ssl)://(?P<host>[^:]+):(?P<port>\d+)$')

    def __init__(self, protocol, host, port):
        self.protocol = protocol
        self.host = host
        self.port = int(port)

    def __str__(self):
        return '{self.protocol}://{self.host}:{self.port}'.format(self=self)

    @classmethod
    def fromUri(cls, uri):
        """
        :param uri:
        :type uri: str
        :return:
        :rtype: Broker
        """
        return cls(**cls._REGEX_URI.match(uri).groupdict())

    def __getitem__(self, item):
        return getattr(self, item)
