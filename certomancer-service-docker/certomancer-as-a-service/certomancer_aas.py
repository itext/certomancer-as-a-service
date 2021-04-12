"""
WSGI frontend for Certomancer "as a service".


Essentially, this module adds an extra endpoint to Certomancer that
allows test setups to submit their own config. The results are cached in Redis.

Note:
    This module doesn't take much in the way of security or DoS-related
    precautions.
    While Certomancer doesn't handle any sensitive data, you should still apply
    standard DevOps common sense when deploying it, even on an internal network.

    Also, the module assumes that the redis backend is available without
    authentication, since it's intended to be deployed in a Docker network
    together with a redis container.

(c) 2021, iText Group NV
"""

import logging
import base64
import json
from dataclasses import dataclass
from typing import Optional, Dict

import redis
import hashlib

import yaml
from asn1crypto import x509
from certomancer.config_utils import ConfigurationError
from certomancer.integrations import animator
from certomancer import registry, config_utils
from certomancer.registry import ArchLabel, CertLabel

from werkzeug import Request, Response
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.exceptions import NotFound, HTTPException, MethodNotAllowed, \
    BadRequest


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Settings(config_utils.ConfigurableMixin):
    redis_host: str
    """Redis host"""

    key_dir: str
    """Directory relative to which key paths are computed."""

    redis_port: int = 6379
    """Redis port"""

    config_search_dir: Optional[str] = None
    """Directory to scan for PKI architecture files."""

    redis_cert_ttl: int = 3600
    """
    Time to keep certificates around in the redis cache (in seconds)
    """

    redis_arch_ttl: int = 3600 * 48
    """
    Time to keep architecture configurations around in the redis cache
    (in seconds).
    """


def fmt_arch_config_name(arch: ArchLabel):
    return f'certomancer_{arch}_config'


class RedisBackedCertCache:

    def __init__(self, redis_instance: redis.Redis, arch: ArchLabel,
                 ttl: int):
        self.redis = redis_instance
        self.arch = arch
        self.ttl = ttl

        # this is reinitialised on every request, so we just dump everything
        self._cache: Dict[CertLabel, x509.Certificate] = {}

    def _fmt_item_name(self, item):
        return f'certomancer_{self.arch}_cert_{item}'

    def __getitem__(self, item):
        try:
            cert = self._cache[item]
            logger.debug(
                "cert '%s' retrieved from local cache for arch '%s'",
                item, self.arch
            )
            return cert
        except KeyError:
            pass

        result = self.redis.get(self._fmt_item_name(item))
        if result is None:
            raise KeyError(item)
        cert: x509.Certificate = x509.Certificate.load(result)
        logger.debug(
            "cert '%s' retrieved from redis for arch '%s'", item, self.arch
        )
        self._cache[item] = cert
        return cert

    def __setitem__(self, item, value):
        if not isinstance(value, x509.Certificate):
            raise TypeError
        item_name = self._fmt_item_name(item)
        self.redis.set(item_name, value.dump(), ex=self.ttl)
        self._cache[item] = value
        logger.debug(
            "cert '%s' inserted into cache for arch '%s'", item, self.arch
        )


def b64_asn1(obj):
    return base64.b64encode(obj.dump()).decode('ascii')


def bundle_cert(pki_arch: registry.PKIArchitecture,
                cert_spec: registry.CertificateSpec):
    cert_label = cert_spec.label
    cert = pki_arch.get_cert(cert_label)
    bundle = {
        'cert': b64_asn1(cert),
        'other_certs': [label.value for label in pki_arch.get_chain(cert_label)]
    }

    # bundle key if available
    if pki_arch.is_subject_key_available(cert_label):
        key = pki_arch.key_set.get_private_key(cert_spec.subject_key)
        bundle['key'] = b64_asn1(key)

    return bundle


def jsonify_pki_arch(pki_arch: registry.PKIArchitecture):

    certs_dict = {
        cert_spec.label.value: bundle_cert(pki_arch, cert_spec)
        for iss, iss_certs in pki_arch.enumerate_certs_by_issuer()
        for cert_spec in iss_certs
    }

    services = pki_arch.service_registry
    service_dict = {
        'time_stamping': {
            srv.label.value: srv.url
            for srv in services.list_time_stamping_services()
        },
        'ocsp': {
            srv.label.value: srv.url for srv in services.list_ocsp_responders()
        },
        'crl_repo': {
            srv.label.value: srv.url for srv in services.list_crl_repos()
        },
        'cert_repo': {
            srv.label.value: srv.url for srv in services.list_cert_repos()
        },
        'plugin': {
            f"{srv.plugin_label}_{srv.label}":
                srv.url for srv in services.list_plugin_services()
        }
    }

    return json.dumps({
        'arch_label': str(pki_arch.arch_label),
        'cert_bundles': certs_dict,
        'services': service_dict
    })


class RedisBackedArchStore(animator.AnimatorArchStore):
    """
    Reimplement AnimatorArchStore to allow on-the-fly reconfs using Redis
    as a cache (and a communication mechanism between the workers).
    """

    def __init__(self, certomancer_config: registry.CertomancerConfig,
                 settings: Settings):

        self.certomancer_config = certomancer_config
        self.settings = settings
        self.redis = redis.Redis(
            host=settings.redis_host, port=settings.redis_port
        )

        super().__init__(certomancer_config.pki_archs)

    def __getitem__(self, item: ArchLabel):
        # Check predefined architectures
        try:
            return self.architectures[item]
        except KeyError:
            pass

        # if the specified architecture is not in the local cache, try to
        # grab the config from redis
        config_from_redis = self.redis.get(fmt_arch_config_name(item))
        if config_from_redis is None:
            raise NotFound()
        else:
            return self.load_from_yaml(item, config_from_redis)

    def load_from_yaml(self, arch: ArchLabel, config: bytes) \
            -> registry.PKIArchitecture:

        config = config.decode('utf8')
        parsed_config = yaml.safe_load(config)
        settings = self.settings
        parsed = registry.PKIArchitecture.build_architecture(
            arch_label=arch, cfg=parsed_config,
            key_sets=self.certomancer_config.key_sets,
            external_url_prefix=self.certomancer_config.external_url_prefix,
            cert_cache=RedisBackedCertCache(
                self.redis, arch, ttl=settings.redis_cert_ttl,
            )
        )
        return parsed

    def register_new_architecture(self, config) -> registry.PKIArchitecture:
        # There are probably better hashes than SHA-1 for bucketing purposes,
        # but meh.
        config_hash = hashlib.sha1(config).digest()
        arch_label = ArchLabel(config_hash.hex())

        # Here's the rationale for always performing SET EX in this scenario.
        # There are two cases:
        #  - the config hash doesn't exist in redis
        #    Then we obviously want to insert it
        #  - the config hash matches one that exists in redis
        #    In this case, we want to make sure that the TTL for the
        #    configuration in redis gets reset. Doing this through a normal
        #    SET allows us to do that without incurring the risk of a race
        #    condition. The TTL on any potential cached certs is a non-issue.

        # The only drawback of this strategy is that the entire config is sent
        #  to redis unconditionally, but the overhead for that should be
        #  negligible.
        # I *think* SET EX NX would not cause the TTL to be bumped
        #  (but I'm not sure). If so, that's not an option.
        # An alternative idea: do an EXISTS check + EXPIRE
        #  in a pipeline with a WATCH and a conditional SET at the end,
        #  but I'll file that under "premature optimisation".

        try:
            arch = self.load_from_yaml(arch_label, config)
        except (yaml.YAMLError, ConfigurationError) as e:
            raise BadRequest(str(e))
        self.redis.set(
            fmt_arch_config_name(arch_label), config,
            ex=self.settings.redis_arch_ttl
        )
        return arch

    def __call__(self, environ, start_response):
        request = Request(environ)
        try:
            if request.path != '/':
                raise NotFound()
            elif request.method != 'POST':
                raise MethodNotAllowed()
            config_data = request.stream.read()
            pki_arch = self.register_new_architecture(config_data)
            json_data = jsonify_pki_arch(pki_arch)
            resp = Response(json_data, mimetype='application/json')

        except HTTPException as e:
            resp = e

        return resp(environ, start_response)


class CertomancerAsAService:

    def __init__(self, initial_config, settings: Settings):
        cfg = dict(initial_config)
        cfg.setdefault('pki-architectures', {})
        self.settings = settings

        self.certomancer_config = cfg_obj = registry.CertomancerConfig(
            cfg, key_search_dir=settings.key_dir,
            config_search_dir=settings.config_search_dir
        )
        self.arch_store = arch_store = RedisBackedArchStore(
            certomancer_config=cfg_obj, settings=settings
        )

        self.animator = animator.Animator(arch_store, with_web_ui=False)

        self._app = DispatcherMiddleware(
            self.animator, {'/config': self.arch_store}
        )

    def __call__(self, environ, start_response):
        return self._app(environ, start_response)


def logging_setup(level):
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)

    for name in ('certomancer', __name__):
        _logger = logging.getLogger(name)
        _logger.setLevel(level)
        _logger.addHandler(handler)


def run_cli():
    from werkzeug.serving import run_simple
    import sys

    with open(sys.argv[1], 'r') as inf:
        cfg_data = yaml.safe_load(inf)
    sett = Settings.from_config(cfg_data.pop('on-demand-settings'))
    run_simple(
        '127.0.0.1', 9000, CertomancerAsAService(cfg_data, sett)
    )


if __name__ == '__main__':
    logging_setup(logging.DEBUG)
    logger.debug("Running certomancer_aas development server...")
    run_cli()
