from _ssl import CERT_REQUIRED, CERT_NONE
from ssl import _DEFAULT_CIPHERS


class SSLConfig(object):
    defaultSSLOptions = [
        'OP_NO_SSLv2',
        'OP_NO_SSLv3',
        'OP_NO_COMPRESSION',
        'OP_CIPHER_SERVER_PREFERENCE',
        'OP_SINGLE_DH_USE',
        'OP_SINGLE_ECDH_USE'
    ]

    def __init__(self,
                 verifyCertificate=True, sslVersion='SSLv23', options=defaultSSLOptions, ciphers=_DEFAULT_CIPHERS,
                 certFile=None, keyFile=None, keyfilePassword=None,
                 caFile=None, caPath=None):
        """
        SSL options for both sync and async connections.
        Defaults should work fine for most situations.
        Set verifyCertificate=False if you do not wish to verify certs.
        Typicall
        Only change if you know what you're doing.

        :param verifyCertificate: Valid inputs are: True (CERT_REQUIRED), False (CERT_NONE)
                                  Defaults to True.
        :type verifyCertificate: bool
        :param sslVersion: Valid inputs: 'SSLv2', 'SSLv23', 'SSLv3', 'TLSv1', 'TLSv1_1', 'TLSv1_2'
                            defaults to 'SSLv23'
        :type sslVersion: int
        :param options: SSL options. Warnings will raise for invalid options.
                        defaults to ['OP_NO_SSLv2', 'OP_NO_SSLv3', 'OP_NO_COMPRESSION', 'OP_CIPHER_SERVER_PREFERENCE', 'OP_SINGLE_DH_USE', 'OP_SINGLE_ECDH_USE']
        :type options: list[str]
        :param ciphers: defaults to 'ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:!eNULL:!MD5'
        :type ciphers: str
        :param certFile: path to a file of concatenated CA certificates in PEM format. Passed through to :meth:`ssl.SSLContext.load_verify_locations` See `SSL Documentation`_ for details
        :type certFile: str
        :param keyFile: path to a directory containing several CA certificates in PEM format. Passed through to :meth:`ssl.SSLContext.load_verify_locations` See `SSL Documentation`_ for details
        :type keyFile: str
        :param keyfilePassword: path to a directory containing several CA certificates in PEM format. Passed through to :meth:`ssl.SSLContext.load_verify_locations` See `SSL Documentation`_ for details
        :type keyfilePassword: str
        :param caFile: path to a file of concatenated CA certificates in PEM format. Passed through to :meth:`ssl.SSLContext.load_verify_locations` See `SSL Documentation`_ for details
        :type caFile: str
        :param caPath: path to a directory containing several CA certificates in PEM format. Passed through to :meth:`ssl.SSLContext.load_verify_locations` See `SSL Documentation`_ for details
        :type caPath: str

        .. _SSL Documentation: https://docs.python.org/2.7/library/ssl.html#ssl.SSLContext.load_verify_locations
        """
        self.sslVersion = sslVersion
        self.certReqs = CERT_REQUIRED if verifyCertificate else CERT_NONE
        self.options = options
        self.ciphers = ciphers
        self.keyFile = keyFile
        self.certFile = certFile
        self.keyfilePassword = keyfilePassword
        self.caFile = caFile
        self.caPath = caPath


class StompConfig(object):
    """This is a container for those configuration options which are common to both clients (sync and async) and are needed to establish a STOMP connection. All parameters are available as attributes with the same name of this object.

    :param uri: A failover URI as it is accepted by :class:`~.StompFailoverUri`.
    :param login: The login for the STOMP brokers. The default is :obj:`None`, which means that no **login** header will be sent.
    :param passcode: The passcode for the STOMP brokers. The default is :obj:`None`, which means that no **passcode** header will be sent.
    :param version: A valid STOMP protocol version, or :obj:`None` (equivalent to the :attr:`DEFAULT_VERSION` attribute of the :class:`~.StompSpec` class).
    :param check: Decides whether the :class:`~.StompSession` object which is used to represent the STOMP sesion should be strict about the session's state: (e.g., whether to allow calling the session's :meth:`~.StompSession.send` when disconnected).
    :param sslConfig: A :class:`~.SSLConfig` that provides the SSL context if ssl is being used for transport.

    .. note :: Login and passcode have to be the same for all brokers because they are not part of the failover URI scheme.

    .. seealso :: The :class:`~.StompFailoverTransport` class which tells you which broker to use and how long you should wait to connect to it, the :class:`~.StompFailoverUri` which parses failover transport URIs.
    """

    def __init__(self, uri, login=None, passcode=None, version=None, check=True, sslConfig=None):
        """

        :param uri:
        :type uri: str
        :param login:
        :type login: str
        :param passcode:
        :type passcode: str
        :param version:
        :type version: str
        :param check:
        :type check: bool
        :param sslConfig:
        :type sslConfig: SSLConfig
        :return:
        :rtype:
        """
        self.uri = uri
        self.login = login
        self.passcode = passcode
        self.version = version
        self.check = check
        self.sslConfig = sslConfig if sslConfig is not None else SSLConfig()
