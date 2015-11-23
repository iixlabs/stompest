import logging
import ssl

log = logging.getLogger(__name__)


def _getSSLVersionFromString(sslVersion):
    try:
        return getattr(ssl, "PROTOCOL_{}".format(sslVersion))
    except AttributeError:
        return ValueError("Invalid sslVersion '{}', valid versions for your system are: {}".format(
            sslVersion, set([x.lstrip("_")[1] for x in dir(ssl) if x.startswith("PROTOCOL_")])
        ))


def syncSSLContext(sslConfig):
    """
    :param sslConfig:
    :type sslConfig: stompest.config.SSLConfig
    :return:
    :rtype: ssl.SSLContext
    """

    def _getKeyPassword():
        return sslConfig.keyfilePassword

    context = ssl.create_default_context(
        ssl.Purpose.CLIENT_AUTH,
        cafile=sslConfig.caFile,
        capath=sslConfig.caPath,
    )
    if sslConfig.sslVersion is not None:
        context.protocol = _getSSLVersionFromString(sslConfig.sslVersion)
    if sslConfig.options is not None:
        for option in sslConfig.options:
            try:
                context.options |= getattr(ssl, option)
            except AttributeError:
                log.warning("Invalid ssl option for this system: '{}', ignoring...".format(option))
    if sslConfig.ciphers is not None:
        if getattr(context, 'supports_set_ciphers', True):  # Platform-specific: Python 2.6
            context.set_ciphers(sslConfig.ciphers)
    if sslConfig.certFile is not None:
        context.load_cert_chain(sslConfig.certFile, keyfile=sslConfig.keyFile, password=_getKeyPassword)
    context.verify_mode = sslConfig.certReqs
    return context
