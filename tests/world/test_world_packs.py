"""World packs: every built-in pack validates, loader precedence, validator rules."""

from __future__ import annotations

import datetime as dt
import shutil
from typing import TYPE_CHECKING

import pytest
import yaml

from sandroid.world.generator import format_amount, format_date
from sandroid.world.packs import (
    BUILTIN_DIR,
    PackSet,
    easter,
    holiday_dates,
    validate_pack,
)

if TYPE_CHECKING:
    from pathlib import Path

BUILTIN = PackSet(user_dir=False)
ALL_PACKS = [
    (k, i) for k in ("countries", "languages", "photos") for i in BUILTIN.ids(k)
]


def test_pack_inventory() -> None:
    assert len(BUILTIN.ids("countries")) == 17
    assert len(BUILTIN.ids("languages")) == 14
    assert BUILTIN.ids("photos") == ["manifest"]
    for kind in ("countries", "languages"):
        for pid in BUILTIN.ids(kind):
            assert (BUILTIN_DIR / kind / f"{pid}.SOURCES.md").is_file()
    assert (BUILTIN_DIR / "photos" / "SOURCES.md").is_file()
    assert not (BUILTIN_DIR / "photos" / "files").exists()


@pytest.mark.parametrize(("kind", "pack_id"), ALL_PACKS)
def test_every_pack_validates(kind: str, pack_id: str) -> None:
    report = validate_pack(BUILTIN.get(kind, pack_id), packs=BUILTIN)
    assert report.errors == []
    assert BUILTIN.get(kind, pack_id).data["schema"] == 1.1


def _country_copy(**changes: object) -> dict:
    data = yaml.safe_load((BUILTIN_DIR / "countries" / "de.yaml").read_text("utf-8"))
    data.update(changes)
    return data


def test_validator_flags_errors_and_warnings() -> None:
    data = _country_copy()
    data["address_format"] = "{street} {nonsense}"
    data["phone"]["mobile"]["fiction"].append({"range": "170-16"})
    data["services"] += [
        {"sender": "X", "kind": "bank", "sender_type": "pigeon"},
        {"sender": "Lendy", "kind": "loan", "sender_type": "alphanumeric"},
        {"sender": "Odd", "kind": "astrology", "sender_type": "alphanumeric"},
    ]
    data["holidays"].append({"rule": "easter*2", "name": "Bad"})
    report = validate_pack(data, pack_id="de")
    text = "\n".join(report.errors)
    assert "unknown placeholder {nonsense}" in text
    assert "bad range" in text
    assert "sender_type" in text
    assert "bad date/rule 'easter*2'" in text
    assert not any("Lendy" in e or "loan" in e for e in report.errors + report.warnings)
    assert any("astrology" in w for w in report.warnings)


def test_validator_language_rules() -> None:
    data = yaml.safe_load((BUILTIN_DIR / "languages" / "de.yaml").read_text("utf-8"))
    data["threads"]["friend"].append({"msgs": [["x", "hi"]]})
    data["notes"].append({"text": "Treffen {whenever}"})
    data["call_names"]["mom"] = ["Mama", 3]
    report = validate_pack(data, pack_id="de")
    assert any("must be [o|p, text]" in e for e in report.errors)
    assert any("{whenever}" in e for e in report.errors)
    assert any(e.startswith("call_names.mom") for e in report.errors)
    assert any(w.startswith("weekdays") for w in report.warnings)
    data = yaml.safe_load((BUILTIN_DIR / "languages" / "de.yaml").read_text("utf-8"))
    data["weekdays"] = ["Mo", "Di"]
    assert any(e.startswith("weekdays") for e in validate_pack(data).errors)


def test_user_pack_overrides_builtin(tmp_path: Path) -> None:
    user = tmp_path / "world"
    (user / "countries").mkdir(parents=True)
    data = _country_copy(name="Testland")
    (user / "countries" / "de.yaml").write_text(
        yaml.safe_dump(data, allow_unicode=True), "utf-8"
    )
    extra = _country_copy(country="zz", name="Zedland")
    (user / "countries" / "zz.yaml").write_text(
        yaml.safe_dump(extra, allow_unicode=True), "utf-8"
    )
    packs = PackSet(user_dir=user)
    assert packs.country("de").data["name"] == "Testland"
    assert packs.country("de").builtin is False
    assert packs.country("fr").builtin is True
    assert "zz" in packs.ids("countries")
    assert validate_pack(packs.country("zz"), packs=packs).errors == []
    assert packs.country("de").sha256 != BUILTIN.country("de").sha256


def test_user_dir_from_xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    target = tmp_path / "sandroid" / "world" / "languages"
    target.mkdir(parents=True)
    shutil.copy(BUILTIN_DIR / "languages" / "en.yaml", target / "en.yaml")
    packs = PackSet()
    assert packs.language("en").builtin is False
    assert packs.language("de").builtin is True


def test_holiday_rules() -> None:
    assert easter(2026) == dt.date(2026, 4, 5)
    assert easter(2025) == dt.date(2025, 4, 20)
    assert holiday_dates({"rule": "easter+1"}, 2026) == [dt.date(2026, 4, 6)]
    assert holiday_dates({"rule": "08-mon#-1"}, 2026) == [dt.date(2026, 8, 31)]
    assert holiday_dates({"rule": "11-thu#4"}, 2026) == [dt.date(2026, 11, 26)]
    assert holiday_dates({"rule": "05-sun#2"}, 2026) == [dt.date(2026, 5, 10)]
    assert holiday_dates({"date": "02-29"}, 2026) == []
    assert holiday_dates({"rule": "lunisolar:diwali"}, 2026) == []
    (eid,) = holiday_dates({"rule": "hijri:10-01"}, 2026)
    assert abs((eid - dt.date(2026, 3, 20)).days) <= 2  # observed date, +-2 days


def test_currency_and_date_formats() -> None:
    assert format_amount(1234.5, "49,99 €") == "1.234,50 €"
    assert format_amount(1234.5, "£49.99") == "£1,234.50"
    assert format_amount(1499.4, "₹1,499") == "₹1,499"
    assert format_amount(49900, "Rp49.900") == "Rp49.900"
    assert format_amount(1250, "KSh 1,250.00") == "KSh 1,250.00"
    assert format_amount(7, "R$ 49,90") == "R$ 7,00"
    day = dt.datetime(2026, 3, 7, 16, 5)
    assert format_date(day, "dd.MM.yyyy") == "07.03.2026"
    assert format_date(day, "d/M/yy") == "7/3/26"
    assert format_date(day, "h:mm a") == "4:05 PM"
