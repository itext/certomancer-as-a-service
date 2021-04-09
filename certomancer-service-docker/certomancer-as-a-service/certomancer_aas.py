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
from typing import Optional

import redis
import uuid

import yaml
from asn1crypto import x509
from certomancer.config_utils import ConfigurationError
from certomancer.integrations import animator
from certomancer import registry, config_utils
from certomancer.registry import ArchLabel
from functools import lru_cache

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

    redis_key_ttl_seconds: int = 3600
    """
    Time to keep things around in the redis cache
    """

    local_lru_arch_cache_size: int = 32
    """
    Number of architectures kept around in local cache.
    """

    local_lru_cert_cache_size: int = 16
    """
    Number of certs per architecture kept around in local cache.
    """


def fmt_arch_config_name(arch: ArchLabel):
    return f'certomancer_{arch}_config'


class RedisBackedCertCache:

    def __init__(self, redis_instance: redis.Redis, arch: ArchLabel,
                 ttl: int, lru_size: int):
        self.redis = redis_instance
        self.arch = arch
        self.ttl = ttl
        if lru_size:
            self._get = lru_cache(lru_size)(self._get)

    def _fmt_item_name(self, item):
        return f'certomancer_{self.arch}_cert_{item}'

    def _get(self, item):
        result = self.redis.get(self._fmt_item_name(item))
        if result is None:
            raise KeyError(item)
        logger.debug(
            "cert '%s' retrieved from cache for arch '%s'", item, self.arch
        )
        return x509.Certificate.load(result)

    def __getitem__(self, item):
        return self._get(item)

    def __setitem__(self, item, value):
        # Do not try to invalidate the __getitem__ cache, since
        # the cert cache is intended to be write-once
        if not isinstance(value, x509.Certificate):
            raise TypeError
        item_name = self._fmt_item_name(item)
        self.redis.set(item_name, value.dump(), ex=self.ttl)


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

    return json.dumps({
        'arch_label': str(pki_arch.arch_label),
        'cert_bundles': certs_dict
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
        # LRU cache for architectures to reduce round-trips to redis and
        # reconf operations
        lru_size = settings.local_lru_arch_cache_size
        if lru_size:
            self._get = lru_cache(lru_size)(self._get)
        super().__init__(certomancer_config.pki_archs)

    def __getitem__(self, item):
        return self._get(item)

    def _get(self, arch: ArchLabel):
        # Check predefined architectures
        try:
            return self.architectures[arch]
        except KeyError:
            pass

        # if the specified architecture is not in the local cache, try to
        # grab the config from redis
        config_from_redis = self.redis.get(fmt_arch_config_name(arch))
        if config_from_redis is None:
            raise NotFound()
        else:
            return self.load_from_yaml(arch, config_from_redis)

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
                self.redis, arch, ttl=settings.redis_key_ttl_seconds,
                lru_size=settings.local_lru_cert_cache_size
            )
        )
        return parsed

    def register_new_architecture(self, config) -> registry.PKIArchitecture:
        # TODO: instead of using UUIDs, it might be worth considering
        #  hashing the config itself. It stands to reason that that would
        #  greatly improve caching efficiency for parallel test runs.
        #  The hash would probably have to be seeded by some random value
        #  (shared by all workers), to avoid stale cache contents persisting
        #  between runs. To avoid having to rely on specific UWSGI forking
        #  settings, storing the value in redis on init would probably be ideal.

        arch_label = ArchLabel(str(uuid.uuid4()))

        try:
            arch = self.load_from_yaml(arch_label, config)
        except (yaml.YAMLError, ConfigurationError) as e:
            raise BadRequest(str(e))
        self.redis.set(
            fmt_arch_config_name(arch_label), config,
            ex=self.settings.redis_key_ttl_seconds
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
