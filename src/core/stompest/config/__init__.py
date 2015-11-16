import ssl
from ssl import Purpose, create_default_context


class SSLConfig(object):
    def __init__(self, ssl_version=None, cert_reqs=None, options=None, ciphers=None):
        """
        As a general rule, leave all as default.
        Only change if you know what you're doing.

        :param ssl_version: Valid inputs: ssl.PROTOCOL_SSLv2,
                                          ssl.PROTOCOL_SSLv23,
                                          ssl.PROTOCOL_SSLv3,
                                          ssl.PROTOCOL_TLSv1,
                                          ssl.PROTOCOL_TLSv1_1,
                                          ssl.PROTOCOL_TLSv1_2
                            defaults to ssl.PROTOCOL_SSLv23
        :type ssl_version: int
        :param cert_reqs: Valid inputs are: ssl.CERT_NONE, ssl.CERT_OPTIONAL, ssl.CERT_REQUIRED
                          Defaults to ssl.CERT_REQUIRED.
        :type cert_reqs: int
        :param options: defaults to ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_COMPRESSION |
                                    ssl.OP_CIPHER_SERVER_PREFERENCE | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
        :type options: int
        :param ciphers: defaults to 'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:!eNULL:!MD5:!DSS:!RC4'
        :type ciphers: str
        """
        self.ssl_version = ssl_version
        self.cert_reqs = ssl.CERT_REQUIRED if cert_reqs is None else cert_reqs
        self.options = options
        self.ciphers = ciphers
        self._context = None

    @property
    def context(self):
        """

        :return:
        :rtype: ssl.SSLContext
        """
        if self._context is not None:
            return self._context
        # noinspection PyUnresolvedReferences
        context = create_default_context(Purpose.CLIENT_AUTH)
        if self.ssl_version is not None:
            context.protocol = self.ssl_version
        if self.options is not None:
            context.options |= self.options
        if self.ciphers is not None:
            if getattr(context, 'supports_set_ciphers', True):  # Platform-specific: Python 2.6
                context.set_ciphers(self.ciphers)
        context.verify_mode = self.cert_reqs
        self._context = context
        return context


class StompConfig(object):
    """This is a container for those configuration options which are common to both clients (sync and async) and are needed to establish a STOMP connection. All parameters are available as attributes with the same name of this object.

    :param uri: A failover URI as it is accepted by :class:`~.StompFailoverUri`.
    :param login: The login for the STOMP brokers. The default is :obj:`None`, which means that no **login** header will be sent.
    :param passcode: The passcode for the STOMP brokers. The default is :obj:`None`, which means that no **passcode** header will be sent.
    :param version: A valid STOMP protocol version, or :obj:`None` (equivalent to the :attr:`DEFAULT_VERSION` attribute of the :class:`~.StompSpec` class).
    :param check: Decides whether the :class:`~.StompSession` object which is used to represent the STOMP sesion should be strict about the session's state: (e.g., whether to allow calling the session's :meth:`~.StompSession.send` when disconnected).
    :param ssl_config: A :class:`~.SSLConfig` that provides the SSL context if ssl is being used for transport.

    .. note :: Login and passcode have to be the same for all brokers because they are not part of the failover URI scheme.

    .. seealso :: The :class:`~.StompFailoverTransport` class which tells you which broker to use and how long you should wait to connect to it, the :class:`~.StompFailoverUri` which parses failover transport URIs.
    """

    def __init__(self, uri, login=None, passcode=None, version=None, check=True, ssl_config=None):
        self.uri = uri
        self.login = login
        self.passcode = passcode
        self.version = version
        self.check = check
        self.ssl_config = ssl_config if ssl_config is not None else SSLConfig()
