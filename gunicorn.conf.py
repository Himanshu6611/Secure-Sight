"""Bounded sync workers; reverse proxy must also limit body size and timeouts."""
import json
import os

bind = '0.0.0.0:' + os.getenv('PORT', '5000')
workers = int(os.getenv('WEB_CONCURRENCY', '1'))
worker_class = 'sync'
timeout = 45
graceful_timeout = 15
umask = 0o077
worker_tmp_dir = '/tmp'
forwarded_allow_ips = os.getenv('TRUSTED_PROXY_IPS', '')
if '*' in forwarded_allow_ips:
    raise ValueError('TRUSTED_PROXY_IPS must not trust arbitrary clients')
max_requests = 1000
max_requests_jitter = 100
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 4094
# Application logs exclude URLs/query strings. Do not enable default access logs.
accesslog = None
errorlog = '-'


def on_exit(server):
    server.log.info(json.dumps({'event': 'application_shutdown'}))
