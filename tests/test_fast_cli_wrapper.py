from pathlib import Path


SCRIPT = Path("bin/fast-cli")


def test_fast_cli_bootstraps_virtualenv_and_requirements():
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'VENV_DIR="$ROOT_DIR/.venv"' in text
    assert 'python3-venv' in text
    assert 'python3-pip' in text
    assert '-m venv "$VENV_DIR"' in text
    assert '-r "$REQUIREMENTS"' in text
    assert 'touch "$INSTALL_MARKER"' in text


def test_fast_cli_runs_cli_with_virtualenv_python_and_forwards_args():
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'exec "$VENV_DIR/bin/python" "$ROOT_DIR/cli.py" "$@"' in text
    assert 'set -- --help' in text


def test_fast_cli_repairs_legacy_readonly_database_and_exports():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "repair_cli_state_permissions" in text
    assert 'chown "$uid:$gid" "$db_path"' in text
    assert 'chown -R "$uid:$gid" "$output_dir"' in text
    assert 'ioc_export.csv' in text
    assert 'ioc_export.json' in text
    assert 'ioc-ips' in text
    assert 'Database directory is not writable' in text
    assert 'Export directory is not writable' in text


def test_cli_handles_head_broken_pipe_without_traceback():
    text = Path("cli.py").read_text(encoding="utf-8")
    assert "except BrokenPipeError" in text
    assert "raise SystemExit(0)" in text
