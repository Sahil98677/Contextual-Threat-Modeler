from pathlib import Path

import pytest

import ctm_cli


def test_scanner_source_is_passed_to_engine(monkeypatch, tmp_path, capsys):
    export = tmp_path / "results.jsonl"
    export.write_text("{}\n", encoding="utf-8")
    calls = {}

    monkeypatch.setattr(ctm_cli, "run_scanner", lambda scanner, path: calls.update(scanner=scanner, path=path) or [])
    monkeypatch.setattr(ctm_cli, "render_console", lambda results: "ok")
    monkeypatch.setattr("sys.argv", ["ctm", "--scanner", "nuclei", "--export", str(export)])

    assert ctm_cli.main() == 0
    assert calls == {"scanner": "nuclei", "path": str(export)}
    assert capsys.readouterr().out.strip() == "ok"


def test_export_requires_scanner(monkeypatch):
    monkeypatch.setattr("sys.argv", ["ctm", "--export", "results.jsonl"])
    with pytest.raises(SystemExit):
        ctm_cli.main()


def test_scanner_requires_export(monkeypatch):
    monkeypatch.setattr("sys.argv", ["ctm", "--scanner", "nuclei"])
    with pytest.raises(SystemExit):
        ctm_cli.main()
