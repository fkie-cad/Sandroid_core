"""Tests for sandroid.core.privacy_markers (identity-profile marker search)."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.parse

import pytest

from sandroid.core.privacy_markers import (
    MIN_NEEDLE_LEN,
    Marker,
    build_needles,
    snippet,
)

AD_ID = "cafe0001-7f3a-4000-8000-c0ffee00a1d0"
EMAIL = "Canary.7f3a9c2e@example.org"
PHONE = "+4930555012345"


def _transforms(hits, marker_id):
    return {h.transform for h in hits if h.marker_id == marker_id}


def test_plain_value_in_json_is_found_case_insensitively():
    needles = build_needles([Marker("ad_id", AD_ID, kind="uuid", label="Ad ID")])
    body = json.dumps({"gaid": AD_ID.upper(), "x": 1}).encode()

    hits = needles.scan(body)

    assert [(h.label, h.transform, h.confidence) for h in hits] == [
        ("Ad ID", "value", "high")
    ]
    assert body[hits[0].offset : hits[0].end].lower() == AD_ID.encode()


def test_uuid_without_dashes():
    needles = build_needles([Marker("ad_id", AD_ID, kind="uuid")])
    hits = needles.scan(b"id=" + AD_ID.replace("-", "").encode())
    assert _transforms(hits, "ad_id") == {"strip_dashes(value)"}


def test_url_encoded_email_in_query_string():
    needles = build_needles([Marker("email", EMAIL, kind="email")])
    query = "https://t.example/c?u=" + urllib.parse.quote(EMAIL, safe="")
    assert _transforms(needles.scan(query), "email") == {"url(value)"}


@pytest.mark.parametrize("prefix_len", range(6))
@pytest.mark.parametrize("encode", [base64.b64encode, base64.urlsafe_b64encode])
def test_base64_at_every_alignment(prefix_len, encode):
    needles = build_needles([Marker("email", EMAIL, kind="email")])
    blob = encode(b"{" * prefix_len + EMAIL.encode() + b'","t":1}')

    transforms = _transforms(needles.scan(b"payload=" + blob), "email")

    assert transforms & {"base64(value)", "base64url(value)"}


@pytest.mark.parametrize("algo", ["md5", "sha1", "sha256"])
def test_hashed_lowercase_email_hex_and_base64(algo):
    needles = build_needles([Marker("email", EMAIL, kind="email")])
    digest = hashlib.new(algo, EMAIL.lower().encode()).digest()

    hex_hits = needles.scan(b'{"em":"' + digest.hex().upper().encode() + b'"}')
    b64_hits = needles.scan(base64.b64encode(digest))

    assert _transforms(hex_hits, "email") == {f"{algo}(lower(value))"}
    assert _transforms(b64_hits, "email") == {f"base64({algo}(lower(value)))"}


def test_phone_digits_and_00_forms():
    needles = build_needles([Marker("phone", PHONE, kind="phone")])
    assert _transforms(needles.scan(b"msisdn=4930555012345&"), "phone") == {
        "digits(value)"
    }
    assert _transforms(needles.scan(b"tel:004930555012345"), "phone") == {
        "intl_00(value)"
    }
    # The digits form lies inside the E.164 match: reported once, as the value.
    assert _transforms(needles.scan(PHONE.encode()), "phone") == {"value"}


def test_extra_forms_from_the_caller():
    needles = build_needles(
        [Marker("phone", PHONE, kind="phone", forms=("030 555012345",))]
    )
    assert needles.scan(b"Tel. 030 555012345")


def test_mac_separator_variants():
    needles = build_needles([Marker("bssid", "02:ca:fe:7e:57:01", kind="mac")])
    assert needles.scan(b"02-CA-FE-7E-57-01")
    assert needles.scan(b"bssid=02cafe7e5701")


def test_coordinates_rounded_truncated_and_pair_boost():
    needles = build_needles(
        [
            Marker("lat", "50.734170", kind="latitude", group="gps"),
            Marker("lon", "7.098230", kind="longitude", group="gps"),
        ]
    )

    lone = needles.scan(b'{"lat":50.7342}')
    pair = needles.scan(b'{"lat":50.7342,"lng":7.0982}')

    assert [(h.transform, h.confidence) for h in lone] == [
        ("round(value, 4)", "medium")
    ]
    assert {h.marker_id: h.confidence for h in pair} == {"lat": "high", "lon": "high"}


def test_weaker_form_inside_stronger_one_is_reported_once():
    needles = build_needles([Marker("lat", "50.734170", kind="latitude")])
    hits = needles.scan(b"lat=50.73417000000001")
    assert len(hits) == 1
    assert hits[0].confidence == "high"


def test_coordinate_e7_integer():
    needles = build_needles([Marker("lat", "50.734170", kind="latitude")])
    assert _transforms(needles.scan(b'"latE7":507341700'), "lat") == {"e7(value)"}


def test_utf16_text_in_binary_file():
    needles = build_needles([Marker("name", "Kanari 7f3a9c2e", kind="text")])
    blob = b"\x00\x01SQLite" + "Kanari 7f3a9c2e".encode("utf-16-le") + b"\xff"
    assert _transforms(needles.scan(blob), "name") == {"utf16(value)"}


def test_non_ascii_value():
    needles = build_needles([Marker("name", "Jürgen Kanari 7f3a", kind="text")])
    assert needles.scan("Name: Jürgen Kanari 7f3a".encode())


def test_short_values_produce_no_plain_needle():
    needles = build_needles([Marker("pin", "1234", kind="text")])
    assert all(len(n.pattern) >= MIN_NEEDLE_LEN for n in needles.needles)
    assert not needles.scan(b"year 1234 and 12345")


def test_empty_value_and_unknown_kind():
    assert len(build_needles([Marker("x", "  ")])) == 0
    with pytest.raises(ValueError):
        Marker("x", "y", kind="nope")


def test_no_false_positive_on_unrelated_traffic():
    needles = build_needles(
        [
            Marker("ad_id", AD_ID, kind="uuid"),
            Marker("email", EMAIL, kind="email"),
            Marker("phone", PHONE, kind="phone"),
        ]
    )
    other = json.dumps(
        {"id": "3f2b9a10-1111-4000-8000-000000000000", "mail": "a@example.org"}
    )
    assert needles.scan(other.encode()) == []


def test_snippet_marks_the_match_and_hides_binary():
    needles = build_needles([Marker("ad_id", AD_ID, kind="uuid")])
    data = b"\x00\x01gaid=" + AD_ID.encode() + b"&x=1"
    before, match, after = snippet(data, needles.scan(data)[0], width=8)
    assert (before, match, after) == ("  gaid=", AD_ID, "&x=1")  # no glyphs


def test_scan_is_fast_enough_for_flow_bodies():
    markers = [Marker(f"id{i}", f"c0ffee00{i:08x}", kind="hex_id") for i in range(20)]
    markers += [Marker("email", EMAIL, kind="email"), Marker("ad", AD_ID, "uuid")]
    needles = build_needles(markers)
    body = (b'{"k":"' + b"x" * 60 + b'"},') * 1000  # ~64 KiB

    start = time.perf_counter()
    needles.scan(body)
    assert time.perf_counter() - start < 0.5


def test_uuid_as_raw_16_bytes_and_base64_of_them():
    import uuid

    needles = build_needles([Marker("ad_id", AD_ID, kind="uuid")])
    raw = uuid.UUID(AD_ID).bytes
    assert _transforms(needles.scan(b"\x0a\x10" + raw + b"\x18"), "ad_id") == {
        "bytes(value)"
    }
    assert _transforms(needles.scan(base64.b64encode(b"\x0a\x10" + raw)), "ad_id") == {
        "base64(bytes(value))"
    }


def test_coordinate_as_protobuf_double():
    import struct

    needles = build_needles([Marker("lat", "50.734170", kind="latitude")])
    proto = b"\x09" + struct.pack("<d", 50.73417)  # field 1, wire type 1 (64-bit)
    assert _transforms(needles.scan(proto), "lat") == {"double_le(value)"}


def test_max_needle_len_for_chunk_overlap():
    needles = build_needles([Marker("email", EMAIL, kind="email")])
    assert needles.max_needle_len == max(len(n.pattern) for n in needles.needles)
    assert build_needles([]).max_needle_len == 0


def _gps():
    return build_needles(
        [
            Marker("lat", "52.520008", kind="latitude", group="gps"),
            Marker("lon", "13.404954", kind="longitude", group="gps"),
        ]
    )


def test_pair_boost_needs_the_two_close_together():
    needles = _gps()
    near = needles.scan(b"lat=52.520&lon=13.405")
    assert {h.marker_id: h.confidence for h in near} == {"lat": "high", "lon": "high"}
    # A price and a weight a kilobyte apart are no GPS fix.
    far = needles.scan(b"price=52.520&" + b"x" * 1024 + b"&weight=13.405")
    assert {h.marker_id for h in far} == {"lat", "lon"}
    assert "high" not in {h.confidence for h in far}


def test_pair_boost_only_raises_the_hits_near_a_partner():
    needles = _gps()
    data = b"a=52.520 " + b"x" * 400 + b" lat=52.520,lon=13.405"
    lats = sorted(
        (h.offset, h.confidence) for h in needles.scan(data) if h.marker_id == "lat"
    )
    assert [c for _o, c in lats] == ["low", "high"]


def test_no_float_needles_and_no_short_needles():
    needles = _gps()
    transforms = {n.transform for n in needles.needles}
    assert not any(t.startswith("float_") for t in transforms)
    assert {"double_le(value)", "double_be(value)"} <= transforms
    assert all(len(n.pattern) >= MIN_NEEDLE_LEN for n in needles.needles)


def test_base64_never_raises_confidence():
    needles = _gps()
    base64_low = [
        n
        for n in needles.needles
        if n.transform.startswith("base64") and "3)" in n.transform
    ]
    assert base64_low
    # 3 decimals is "low"; a short base64 fragment of it stays low.
    assert {n.confidence for n in base64_low} == {"low"}
