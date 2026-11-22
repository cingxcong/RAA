"""Engine catalogue and diagnostics tests."""

from __future__ import annotations

from raa.services.engines import ENGINE_CATALOGUE, EngineService


def test_catalogue_is_unique_and_classified() -> None:
    ids = [spec.id for spec in ENGINE_CATALOGUE]
    assert len(ids) == len(set(ids))
    assert len(ids) == 24
    assert {spec.tier for spec in ENGINE_CATALOGUE} <= {1, 2, 3}
    for spec in ENGINE_CATALOGUE:
        assert spec.license
        assert spec.capabilities
        assert spec.integration in {"native", "library", "sidecar", "service"}


def test_discovery_covers_every_engine() -> None:
    service = EngineService()
    statuses = service.discover()
    assert len(statuses) == len(ENGINE_CATALOGUE)
    summary = service.summary()
    assert summary["catalogued"] == len(ENGINE_CATALOGUE)
    assert summary["installed"] + summary["missing"] == summary["catalogued"]


def test_engine_payload_has_no_nested_dataclass() -> None:
    status = EngineService().discover()[0]
    payload = status.to_dict()
    assert "spec" not in payload
    assert isinstance(payload["capabilities"], list)
    assert isinstance(payload["commands"], list)
    assert isinstance(payload["python_modules"], list)
    assert isinstance(payload["installed"], bool)


def test_license_report_groups() -> None:
    report = EngineService().license_report()
    by_license = report["by_license"]
    classes = report["distribution_classes"]
    assert isinstance(by_license, dict)
    assert "Apache-2.0" in by_license
    assert "JADX" in by_license["Apache-2.0"]
    assert isinstance(classes, dict)
    assert set(classes) == {"permissive", "weak_copyleft", "strong_copyleft"}
    assert "APKiD" in classes["strong_copyleft"]
    assert "Ghidra" not in classes["strong_copyleft"]
