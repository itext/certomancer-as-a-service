
"""
Load Certomancer-as-a-service config from the environment.

(c) 2021, iText Group NV
"""
import logging
import os

import yaml

from certomancer_aas import Settings, CertomancerAsAService, logging_setup


def from_env():
    def _process_env_var(v):
        try:
            return int(v)
        except ValueError:
            pass

        if v.casefold() == 'true':
            return True
        elif v.casefold() == 'false':
            return False

        return v

    # grab all env vars that start with CERTOMANCER_
    settings_dict = {
        k[12:].lower(): _process_env_var(v) for k, v in os.environ.items()
        if k.startswith('CERTOMANCER_')
    }

    # set up logging
    log_level = settings_dict.pop('log_level', 'INFO')
    logging_setup(getattr(logging, log_level))

    # read config from the CERTOMANCER_CONFIG env var
    config_file = settings_dict.pop('config')
    with open(config_file, 'r') as inf:
        cfg_data = yaml.safe_load(inf)
    settings = Settings.from_config(settings_dict)
    return CertomancerAsAService(cfg_data, settings)


app = from_env()
