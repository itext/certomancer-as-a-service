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


import base64
import json
from dataclasses import dataclass
from typing import Optional

import redis
import uuid

import yaml
from asn1crypto import x509
from certomancer.integrations import animator
from certomancer import registry, config_utils
from certomancer.registry import ArchLabel
from functools import lru_cache

from werkzeug import Request, Response
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.exceptions import NotFound, HTTPException, MethodNotAllowed, \
    BadRequest


@dataclass(frozen=True)
class Settings(config_utils.ConfigurableMixin):
    redis_host: str
    """Redis host"""

    key_search_dir: str
    """Directory relative to which key paths are computed."""

    redis_port: int = 6379
    """Redis port"""

    config_search_dir: Optional[str] = None
    """Directory to scan for PKI architecture files."""

    redis_key_ttl_seconds = 3600
    """
    Time to keep things around in the redis cache
    """

    local_lru_arch_cache_size = 32
    """
    Number of architectures kept around in local cache.
    """

    local_lru_cert_cache_size = 16
    """
    Number of certs per architecture kept around in local cache.
    """

    submit_resp_include_pkcs12 = False
    """
    Whether to include PKCS #12 archives for all certs in the packet returned
    after a config submission.
    """


def fmt_arch_config_name(arch: ArchLabel):
    return f'certomancer_{arch}_config'


class RedisBackedCertCache:

    def __init__(self, redis_instance: redis.Redis, arch: ArchLabel,
                 ttl: int, lru_size: int):
        self.redis = redis_instance
        self.arch = arch
        self.ttl = ttl
        self._get = lru_cache(lru_size)(self._get)

    def _fmt_item_name(self, item):
        return f'certomancer_{self.arch}_cert_{item}'

    def _get(self, item):
        result = self.redis.get(self._fmt_item_name(item))
        if result is None:
            raise KeyError(item)
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


def jsonify_pki_arch(pki_arch: registry.PKIArchitecture, include_pkcs12=False):
    itr = pki_arch._dump_certs(
        use_pem=False, flat=True, include_pkcs12=include_pkcs12
    )

    result_dict = {
        name: base64.b64encode(data).decode('ascii')
        for name, data in itr if data is not None
    }
    return json.dumps(result_dict)


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
        cacher = lru_cache(settings.local_lru_arch_cache_size)
        self._get = cacher(self._get)
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
            self.load_from_yaml(arch, config_from_redis)

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
        except yaml.YAMLError:
            raise BadRequest()
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
            json_data = jsonify_pki_arch(
                pki_arch,
                include_pkcs12=self.settings.submit_resp_include_pkcs12
            )
            resp = Response(json_data, mimetype='application/json')

        except HTTPException as e:
            resp = e

        return resp(environ, start_response)


class CertomancerAsAService:

    def __init__(self, initial_config):
        cfg = dict(initial_config)
        cfg.setdefault('pki-architectures', {})
        settings_dict = cfg.pop('on-demand-settings')
        self.settings = settings = Settings.from_config(settings_dict)

        self.certomancer_config = cfg_obj = registry.CertomancerConfig(
            cfg, key_search_dir=settings.key_search_dir,
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


if __name__ == '__main__':

    from werkzeug.serving import run_simple
    import sys

    with open(sys.argv[1], 'r') as inf:
        cfg_data = yaml.safe_load(inf)
    run_simple('127.0.0.1', 9000, CertomancerAsAService(cfg_data))
