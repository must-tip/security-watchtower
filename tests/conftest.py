"""Test bootstrap independent of the caller's working directory."""

from __future__ import annotations

import os
import sys
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
if str(COMPONENT_ROOT) not in sys.path:
    sys.path.insert(0, str(COMPONENT_ROOT))

# Safe deterministic defaults for module-import tests. Individual tests override
# these values when validating failure cases.
os.environ.setdefault("WATCHTOWER_ENV", "production")
os.environ.setdefault("REDIS_PASSWORD", "test-only-redis-password-123456789")
os.environ.setdefault("API_WATCHER_TARGETS", "https://prod.example.test/health")
