from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_collector_runs_as_host_uid_gid():
    deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
    refresh = (ROOT / "refresh_iocs.sh").read_text(encoding="utf-8")
    fast = (ROOT / "bin" / "fast").read_text(encoding="utf-8")
    compose = (ROOT / "docker" / "docker-compose.fast.yml").read_text(encoding="utf-8")

    assert 'HOST_UID="$(id -u)"' in deploy
    assert 'HOST_GID="$(id -g)"' in deploy
    assert '--user "$HOST_UID:$HOST_GID"' in deploy
    assert '--user "$HOST_UID:$HOST_GID"' in refresh
    assert "FAST_HOST_UID" in fast and "FAST_HOST_GID" in fast
    assert 'user: "${FAST_HOST_UID:-1000}:${FAST_HOST_GID:-1000}"' in compose


def test_deploy_repairs_legacy_root_owned_fast_state():
    deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
    assert "/app/ioc_database.db" in deploy
    assert "/app/fast_operations.db" in deploy
    assert "chown -R $HOST_UID:$HOST_GID" in deploy
