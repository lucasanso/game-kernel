import json

from gamekernel.config import DEFAULTS, Settings


def test_defaults_and_persistence(isolated_data_dir):
    s = Settings()
    assert s.get("scan.default_mode") == "deep"
    s.set("scan.max_workers", 999)
    assert s.get("scan.max_workers") == 32  # clamped
    s.set("scan.excluded_extensions", ["PAK", ".Bik", ""])
    s.save()
    again = Settings()
    assert again.get("scan.excluded_extensions") == [".bik", ".pak"]


def test_corrupt_file_falls_back_to_defaults(isolated_data_dir):
    s = Settings()
    s.path.write_text("{not json", encoding="utf-8")
    again = Settings()
    assert again.get("scan.default_mode") == DEFAULTS["scan"]["default_mode"]
    assert s.path.with_suffix(".corrupt.json").exists()


def test_unknown_keys_are_dropped(isolated_data_dir):
    s = Settings()
    s.path.write_text(json.dumps({"scan": {"evil": 1, "max_workers": 2}, "other": 3}), encoding="utf-8")
    again = Settings()
    assert again.get("scan.evil") is None and again.get("other") is None
    assert again.get("scan.max_workers") == 2
