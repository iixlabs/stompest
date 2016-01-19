import re


class Broker(object):
    PROTOCOL_TCP = 'tcp'
    PROTOCOL_SSL = 'ssl'
    PROTOCOLS = set([PROTOCOL_TCP, PROTOCOL_SSL])

    _REGEX_URI = re.compile('^(?P<protocol>{})://(?P<host>[^:]+):(?P<port>\d+)$'.format('|'.join(PROTOCOLS)))

    def __init__(self, protocol, host, port):
        if protocol not in self.PROTOCOLS:
            raise ValueError('Invalid protocol "{}". Valid protocols are {}'.format(protocol, self.PROTOCOLS))
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
        try:
            return cls(**cls._REGEX_URI.match(uri).groupdict())
        except AttributeError:
            raise ValueError('Invalid URI, must match regex "{}"'.format(cls._REGEX_URI.pattern))

    def __getitem__(self, item):
        return getattr(self, item)

    def __eq__(self, other):
        assert isinstance(other, Broker)
        return self.protocol == other.protocol and self.host == other.host and self.port == other.port
