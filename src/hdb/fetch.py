"""Descargas HTTP con stdlib, respetando el proxy del entorno."""

from __future__ import annotations

import json
import urllib.request
from typing import Any

USER_AGENT = "hdb/0.1 (+bug bounty scope tool)"


def get_json(url: str, timeout: int = 120) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))
