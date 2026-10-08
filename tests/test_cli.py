from ctm_cli import main


def test_history_dir_creates_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["ctm", "--history-dir", str(tmp_path)])
    assert main() == 0
    assert list(tmp_path.glob("*.json"))
