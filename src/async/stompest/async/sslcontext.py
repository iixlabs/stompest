from stompest.protocol.sslspec import StompSSLSpec

from OpenSSL import SSL
from twisted.internet import reactor
from twisted.internet.endpoints import SSL4ClientEndpoint
from twisted.internet.ssl import ClientContextFactory

from stompest.async.util import log


class AsyncClientSSLContextFactory(ClientContextFactory):
    __SSLVersions = set([x for x in dir(SSL) if x.endswith('_METHOD')])
    validSSLVersionStrings = set([x.rsplit('_')[0] for x in __SSLVersions])
    validSSLVersionInt = set([getattr(SSL, x) for x in __SSLVersions])
    validSSLOptions = set([x for x in dir(SSL) if x.startswith('OP_')])

    _ssl_to_openssl_verify_mapping = {
        StompSSLSpec.CERT_NONE: SSL.VERIFY_NONE,
        StompSSLSpec.CERT_OPTIONAL: SSL.VERIFY_PEER,
        StompSSLSpec.CERT_REQUIRED: SSL.VERIFY_PEER + SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
    }

    def __init__(self, method=StompSSLSpec.SSLv23, verify=StompSSLSpec.CERT_REQUIRED, options=None, ciphers=None,
                 certFile=None, keyFile=None, keyFilePassword=None, caFile=None, caPath=None):
        self.method = self._parseSSLMethod(method)
        self.options = self._parseSSLOptions(options)
        self.verify = verify
        self.ciphers = ciphers
        self.certFile = certFile
        self.keyFile = keyFile
        self.keyFilePassword = keyFilePassword
        self.caFile = caFile
        self.caPath = caPath

    def _parseSSLMethod(self, method):
        if isinstance(method, int):
            if method in self.validSSLVersionInt:
                return method
            else:
                raise ValueError('Invalid sslVersion {}, Valid values for sslVersion are {}'.format(
                    method, self.validSSLVersionStrings
                )
                )
        else:
            try:
                return getattr(SSL, "{}_METHOD".format(method))
            except AttributeError:
                raise ValueError(
                    'Invalid sslVersion (method) "{}". Valid versions are {}'.format(
                        method, self.validSSLVersionStrings
                    )
                )

    def _parseSSLOptions(self, options):
        result = []
        if options is not None:
            for option in options:
                try:
                    result.append(getattr(SSL, option))
                except AttributeError:
                    log.warning('Invalid SSL option for this system: "{}", ignoring...'.format(option))
        return result

    @staticmethod
    def _verifyCallback(cnx, x509, err_no, err_depth, return_code):
        return err_no == 0

    def _getKeyPassword(self):
        return self.keyFilePassword

    def getContext(self):
        """
        :return: an OpenSSL context used by Twisted
        :rtype: OpenSSL.SSL.Context
        """
        try:
            ctx = self._contextFactory(self.method)
        except AttributeError:
            raise ValueError(
                'Invalid sslVersion (method). Valid versions are {}'.format(self.validSSLVersionStrings)
            )
        for op in self.options:
            ctx.set_options(op)
        if self.caFile is not None or self.caPath is not None:
            ctx.load_verify_locations(self.caFile, self.caPath)
        if self.ciphers is not None:
            ctx.set_cipher_list(self.ciphers)
        if self.certFile is not None:
            self.keyFile = self.keyFile if self.keyFile is not None else self.certFile
            ctx.use_certificate_file(self.certFile)
        if self.keyFile is not None:
            ctx.use_privatekey_file(self.keyFile)
        if self.keyFilePassword is not None:
            ctx.set_passwd_cb(self._getKeyPassword)
        ctx.set_verify(self._ssl_to_openssl_verify_mapping[self.verify], self._verifyCallback)
        return ctx


def asyncContextFactory(config):
    """

    :param config:
    :type config: stompest.config.StompConfig
    :return:
    :rtype: AsyncClientSSLContextFactory
    """
    return AsyncClientSSLContextFactory(
        method=config.sslConfig.sslVersion,
        verify=config.sslConfig.certReqs,
        options=config.sslConfig.options,
        ciphers=config.sslConfig.ciphers,
        certFile=config.sslConfig.certFile,
        keyFile=config.sslConfig.keyFile,
        keyFilePassword=config.sslConfig.keyfilePassword,
        caFile=config.sslConfig.caFile,
        caPath=config.sslConfig.caPath,
    )


def SSLClientEndpointFactory(broker, config, timeout=None):
    """

    :param broker:
    :type broker: stompest.protocol.broker.Broker
    :param config:
    :type config: stompest.config.StompConfig
    :param timeout:
    :type timeout: int
    :return:
    :rtype: twisted.internet.endpoints.SSL4ClientEndpoint
    """
    return SSL4ClientEndpoint(
        reactor,
        host=broker.host,
        port=broker.port,
        sslContextFactory=asyncContextFactory(config),
        timeout=timeout
    )
