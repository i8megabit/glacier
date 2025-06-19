#!/usr/bin/env python3

# All configs for execute script
from os import getenv

def get_config():
    return {
        "version": "2.3.0",
        "except_local_connection": True,
        "except_ipv6": False,
        "outgoing_ports": 1024,
        "local_address": ["127.0.0.1", "::1", "::ffff:127.0.1"],
        "local_interfaces": ["lo"],
        "file_name": "report_analyzer",
        "supported_formats": ["yaml", "json"],
        "date_format": "%d.%m.%Y %H:%M:%S",
        "delay": {
            "min": 0,
        },
        "s3": {
            "url": getenv('S3_ENDPOINT_URL'),
            "user": getenv('S3_ACCESS_KEY_ID'),
            "access_key": getenv('S3_ACCESS_SECRET_KEY'),
            "region": "endpoint",
            "bucket": "analyzer",
            "reports_prefix": "reports/",
            "default_region": "us-east-1"
        },
        "analysis": {
            "max_connections": 50,
            "max_ports": 100,
            "max_changes_log": 50,
            "max_udp_connections": 20
        }
    }
