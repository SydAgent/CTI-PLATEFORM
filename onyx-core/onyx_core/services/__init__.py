"""ONYX CTI — Database Services Package.
Supports transparent zero-latency Fallback Mode (STANDALONE_MODE).
"""

import os

if os.environ.get("STANDALONE_MODE") == "true":
    from onyx_core.services.standalone import (
        MockElasticsearchService as ElasticsearchService,
        MockMongoDBService as MongoDBService,
        MockRedisService as RedisService,
    )
else:
    from onyx_core.services.elasticsearch import ElasticsearchService
    from onyx_core.services.mongodb import MongoDBService
    from onyx_core.services.redis import RedisService

__all__ = ["ElasticsearchService", "MongoDBService", "RedisService"]
