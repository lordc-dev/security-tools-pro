import json
import time
import pytest
from unittest.mock import patch
from pathlib import Path

import core.cache as cache_mod
from core.cache import (
    get,
    set,
    get_json,
    set_json,
    get_config,
    set_config,
    cleanup,
    rate_limit,
)


@pytest.fixture
def isolated_cache(tmp_path):
    """Redirect the cache DB to a temp directory for test isolation."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cache_db = cache_dir / "cache.db"

    with patch.object(cache_mod, "CACHE_DIR", cache_dir), \
         patch.object(cache_mod, "CACHE_DB", cache_db):
        yield cache_dir


class TestCacheSetGet:
    def test_set_and_get(self, isolated_cache):
        set("test:key", "hello", ttl=60)
        assert get("test:key") == "hello"

    def test_get_missing(self, isolated_cache):
        assert get("nonexistent") is None

    def test_set_overwrite(self, isolated_cache):
        set("test:key", "v1", ttl=60)
        set("test:key", "v2", ttl=60)
        assert get("test:key") == "v2"

    def test_set_empty_value(self, isolated_cache):
        set("test:key", "", ttl=60)
        assert get("test:key") == ""

    def test_set_large_value(self, isolated_cache):
        large = "x" * 10000
        set("test:large", large, ttl=60)
        assert get("test:large") == large


class TestCacheTTL:
    def test_ttl_expires(self, isolated_cache):
        set("test:key", "value", ttl=0.1)
        assert get("test:key") == "value"
        time.sleep(0.15)
        assert get("test:key") is None

    def test_ttl_not_expired(self, isolated_cache):
        set("test:key", "value", ttl=10)
        time.sleep(0.05)
        assert get("test:key") == "value"

    def test_default_ttl(self, isolated_cache):
        set("nvd:something", "data")
        assert get("nvd:something") == "data"

    def test_zero_ttl_expires_immediately(self, isolated_cache):
        set("test:key", "value", ttl=0)
        time.sleep(0.02)
        assert get("test:key") is None


class TestCacheJson:
    def test_set_json_and_get_json(self, isolated_cache):
        data = {"key": "value", "nested": {"a": 1}}
        set_json("test:json", data, ttl=60)
        result = get_json("test:json")
        assert result == data

    def test_get_json_missing(self, isolated_cache):
        assert get_json("nonexistent") is None

    def test_set_json_list(self, isolated_cache):
        data = [1, 2, 3, {"item": "four"}]
        set_json("test:list", data, ttl=60)
        assert get_json("test:list") == data

    def test_get_json_on_non_json(self, isolated_cache):
        set("test:notjson", "not json data", ttl=60)
        with pytest.raises(json.JSONDecodeError):
            get_json("test:notjson")

    def test_set_json_unicode(self, isolated_cache):
        data = {"message": "café — naïve"}
        set_json("test:unicode", data, ttl=60)
        assert get_json("test:unicode") == data


class TestCacheConfig:
    def test_set_and_get_config(self, isolated_cache):
        set_config("setting1", "value1")
        assert get_config("setting1") == "value1"

    def test_get_config_missing(self, isolated_cache):
        assert get_config("nonexistent") is None

    def test_get_config_default(self, isolated_cache):
        assert get_config("nonexistent", "fallback") == "fallback"

    def test_set_config_overwrite(self, isolated_cache):
        set_config("key", "v1")
        set_config("key", "v2")
        assert get_config("key") == "v2"

    def test_config_separate_from_kv(self, isolated_cache):
        set("same_key", "kv_value", ttl=60)
        set_config("same_key", "config_value")
        assert get("same_key") == "kv_value"
        assert get_config("same_key") == "config_value"


class TestCacheCleanup:
    def test_cleanup_removes_expired(self, isolated_cache):
        set("test:expired", "v1", ttl=0.1)
        set("test:alive", "v2", ttl=60)
        time.sleep(0.15)
        removed = cleanup()
        assert removed == 1
        assert get("test:expired") is None
        assert get("test:alive") == "v2"

    def test_cleanup_nothing_expired(self, isolated_cache):
        set("test:key", "value", ttl=60)
        removed = cleanup()
        assert removed == 0

    def test_cleanup_empty_db(self, isolated_cache):
        removed = cleanup()
        assert removed == 0


class TestRateLimit:
    def test_rate_limit_does_not_raise(self):
        rate_limit("test")
        rate_limit("test")

    def test_rate_limit_default_bucket(self):
        rate_limit()
        rate_limit()

    def test_rate_limit_different_buckets(self):
        rate_limit("nvd")
        rate_limit("epss")
        rate_limit("ghsa")