from stompest.protocol.sslspec import StompSSLSpec


class SSLConfig(object):

    def __init__(self,
                 verifyCertificate=True,
                 sslVersion=StompSSLSpec.SSLv23,
                 options=StompSSLSpec.DEFAULT_SSL_OPTIONS,
                 ciphers=StompSSLSpec.DEFAULT_CIPHERS,
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
        self.certReqs = StompSSLSpec.CERT_REQUIRED if verifyCertificate else StompSSLSpec.CERT_NONE
        self.options = options
        self.ciphers = ciphers
        self.keyFile = keyFile
        self.certFile = certFile
        self.keyfilePassword = keyfilePassword
        self.caFile = caFile
        self.caPath = caPath