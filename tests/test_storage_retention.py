from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_fast_web_reuses_the_collector_image_instead_of_building_twice():
    fast_cli = (ROOT / "bin" / "fast").read_text(encoding="utf-8")
    assert 'up -d --no-build' in fast_cli
    assert 'up -d --build' not in fast_cli


def test_wazuh_retention_policy_covers_time_series_indices_only():
    policy_script = (ROOT / "scripts" / "configure_wazuh_retention.sh").read_text(encoding="utf-8")
    assert "FAST_WAZUH_RETENTION_DAYS" in policy_script
    assert "min_index_age" in policy_script
    assert "wazuh-alerts-4.x-*" in policy_script
    assert "wazuh-archives-4.x-*" in policy_script
    assert "wazuh-monitoring-*" in policy_script
    assert "wazuh-statistics-*" in policy_script
    assert "wazuh-states-" not in policy_script


def test_deployment_rotates_wazuh_alert_files_and_applies_index_policy():
    deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
    assert "ensure_wazuh_log_rotation" in deploy
    assert '("rotate_interval", "1d")' in deploy
    assert '("max_output_size", "20M")' in deploy
    assert "scripts/configure_wazuh_retention.sh" in deploy


def test_docker_logs_and_rotated_wazuh_logs_are_bounded():
    wazuh_override = (ROOT / "docker" / "healthcheck.override.yml").read_text(encoding="utf-8")
    fast_compose = (ROOT / "docker" / "docker-compose.fast.yml").read_text(encoding="utf-8")
    for content in (wazuh_override, fast_compose):
        assert 'max-size: "10m"' in content
        assert 'max-file: "3"' in content
    assert "fast-wazuh-log-retention" in wazuh_override
    assert "find /var/ossec/logs" in wazuh_override
    assert "FAST_WAZUH_RETENTION_DAYS" in wazuh_override


def test_docker_cleanup_never_prunes_persistent_volumes():
    fast_cli = (ROOT / "bin" / "fast").read_text(encoding="utf-8")
    assert "docker image prune -f" in fast_cli
    assert 'docker builder prune -f --filter "until=168h"' in fast_cli
    assert "docker volume prune" not in fast_cli



def test_storage_retention_defaults_and_data_expiry_are_documented():
    guide = (ROOT / "docs" / "DEPLOYMENT_GUIDE.md").read_text(encoding="utf-8")
    assert "7-day index retention" in guide
    assert "permanently removed" in guide
    assert "FAST_WAZUH_RETENTION_DAYS=14" in guide
    assert "FAST_WAZUH_INDEXER_ADMIN_PASSWORD" in guide
