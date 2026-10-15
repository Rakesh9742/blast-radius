"""FalkorDB connection helpers shared by ingest, agent and server."""
import os
from falkordb import FalkorDB

_db = None


def get_db() -> FalkorDB:
    global _db
    if _db is None:
        _db = FalkorDB(host=os.getenv("FALKORDB_HOST", "localhost"), port=int(os.getenv("FALKORDB_PORT", "6379")))
    return _db


def get_graph(name: str | None = None):
    return get_db().select_graph(name or os.getenv("GRAPH_NAME", "mealie"))


def rows(result) -> list[dict]:
    """Convert a FalkorDB QueryResult into a list of dicts keyed by header name."""
    headers = [h[1] if isinstance(h, (list, tuple)) else h for h in result.header]
    return [dict(zip(headers, r)) for r in result.result_set]
