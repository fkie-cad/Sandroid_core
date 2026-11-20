"""Bodies of the seeded Download/Documents files (host side, no device).

Each world file only has a name, a kind and a time; :func:`file_bytes` makes
a small, valid file of the type its extension names: plain text, a one-page
PDF (own minimal writer), minimal OOXML (docx/xlsx/pptx), a plain JPEG/PNG
"scan" (Pillow, no metadata), iCalendar or vCard text. Nothing here carries
host or identity data: the text is the file's title and its date.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import zipfile
from pathlib import PurePosixPath
from xml.sax.saxutils import escape

_TEXT_EXT = {"txt", "csv", "md", "log"}


def file_bytes(name: str, lines: list[str], when: dt.datetime) -> bytes:
    """Return the body of a file named ``name``.

    Args:
        name: The file name; its extension picks the format.
        lines: Text lines (the first is the title).
        when: The file's time (dates inside zip containers).
    """
    ext = PurePosixPath(name).suffix.lower().lstrip(".")
    if ext == "pdf":
        return pdf_bytes(lines)
    if ext == "docx":
        return _docx(lines, when)
    if ext == "xlsx":
        return _xlsx(lines, when)
    if ext == "pptx":
        return _pptx(lines, when)
    if ext in ("jpg", "jpeg", "png"):
        return _image(lines, "PNG" if ext == "png" else "JPEG")
    if ext == "ics":
        return _ics(lines, when)
    if ext == "vcf":
        return _vcf(lines)
    return ("\n".join(lines) + "\n").encode("utf-8")


# ------------------------------------------------------------------- PDF


def _pdf_text(text: str) -> str:
    raw = text.encode("cp1252", "replace").decode("latin-1")
    return raw.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def pdf_bytes(lines: list[str]) -> bytes:
    """A one-page A4 PDF with ``lines`` in Helvetica (WinAnsi encoding)."""
    ops = ["BT", "/F1 16 Tf", "56 780 Td", "22 TL"]
    for i, line in enumerate(lines[:40]):
        if i == 1:
            ops.append("/F1 11 Tf")
        ops.append(f"({_pdf_text(line)}) Tj T*")
    ops.append("ET")
    stream = "\n".join(ops).encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for n, body in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % n + body + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(
        b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
        % (len(objects) + 1, xref)
    )
    return out.getvalue()


# ------------------------------------------------------------------ OOXML


def _zip(parts: dict[str, str], when: dt.datetime) -> bytes:
    stamp = (max(when.year, 1980), when.month, when.day, when.hour, when.minute, 0)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, text in parts.items():
            info = zipfile.ZipInfo(path, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, text.encode("utf-8"))
    return out.getvalue()


_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_CT = "http://schemas.openxmlformats.org/package/2006/content-types"


def _types(overrides: dict[str, str]) -> str:
    items = "".join(
        f'<Override PartName="{p}" ContentType="{c}"/>' for p, c in overrides.items()
    )
    return (
        f'{_XML}<Types xmlns="{_CT}">'
        '<Default Extension="rels" ContentType='
        '"application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        f"{items}</Types>"
    )


def _rels(target: str, kind: str) -> str:
    return (
        f'{_XML}<Relationships xmlns="{_PKG_REL}">'
        f'<Relationship Id="rId1" Type="{kind}" Target="{target}"/></Relationships>'
    )


def _docx(lines: list[str], when: dt.datetime) -> bytes:
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    paras = "".join(f"<w:p><w:r><w:t>{escape(x)}</w:t></w:r></w:p>" for x in lines)
    return _zip(
        {
            "[Content_Types].xml": _types(
                {
                    "/word/document.xml": "application/vnd.openxmlformats-"
                    "officedocument.wordprocessingml.document.main+xml"
                }
            ),
            "_rels/.rels": _rels("word/document.xml", f"{_REL}/officeDocument"),
            "word/document.xml": f'{_XML}<w:document xmlns:w="{w}"><w:body>'
            f"{paras}</w:body></w:document>",
        },
        when,
    )


def _xlsx(lines: list[str], when: dt.datetime) -> bytes:
    s = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    rows = "".join(
        f'<row r="{i}"><c r="A{i}" t="inlineStr"><is><t>{escape(x)}</t></is></c></row>'
        for i, x in enumerate(lines, start=1)
    )
    return _zip(
        {
            "[Content_Types].xml": _types(
                {
                    "/xl/workbook.xml": "application/vnd.openxmlformats-"
                    "officedocument.spreadsheetml.sheet.main+xml",
                    "/xl/worksheets/sheet1.xml": "application/vnd.openxmlformats-"
                    "officedocument.spreadsheetml.worksheet+xml",
                }
            ),
            "_rels/.rels": _rels("xl/workbook.xml", f"{_REL}/officeDocument"),
            "xl/workbook.xml": f'{_XML}<workbook xmlns="{s}" xmlns:r="{_REL}">'
            '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>'
            "</workbook>",
            "xl/_rels/workbook.xml.rels": _rels(
                "worksheets/sheet1.xml", f"{_REL}/worksheet"
            ),
            "xl/worksheets/sheet1.xml": f'{_XML}<worksheet xmlns="{s}">'
            f"<sheetData>{rows}</sheetData></worksheet>",
        },
        when,
    )


def _pptx(lines: list[str], when: dt.datetime) -> bytes:
    """A minimal presentation package (one slide, text only)."""
    p = "http://schemas.openxmlformats.org/presentationml/2006/main"
    a = "http://schemas.openxmlformats.org/drawingml/2006/main"
    text = "".join(f"<a:p><a:r><a:t>{escape(x)}</a:t></a:r></a:p>" for x in lines)
    shape = (
        '<p:sp><p:nvSpPr><p:cNvPr id="2" name="Text"/><p:cNvSpPr/><p:nvPr/>'
        '</p:nvSpPr><p:spPr><a:xfrm><a:off x="457200" y="457200"/>'
        '<a:ext cx="8229600" cy="4525963"/></a:xfrm></p:spPr>'
        f"<p:txBody><a:bodyPr/>{text}</p:txBody></p:sp>"
    )
    tree = (
        '<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/>'
        f"<p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>{shape}</p:spTree></p:cSld>"
    )
    ct = "application/vnd.openxmlformats-officedocument.presentationml."
    return _zip(
        {
            "[Content_Types].xml": _types(
                {
                    "/ppt/presentation.xml": ct + "presentation.main+xml",
                    "/ppt/slides/slide1.xml": ct + "slide+xml",
                }
            ),
            "_rels/.rels": _rels("ppt/presentation.xml", f"{_REL}/officeDocument"),
            "ppt/presentation.xml": f'{_XML}<p:presentation xmlns:p="{p}" '
            f'xmlns:r="{_REL}"><p:sldIdLst><p:sldId id="256" r:id="rId1"/>'
            '</p:sldIdLst><p:sldSz cx="9144000" cy="6858000"/>'
            '<p:notesSz cx="6858000" cy="9144000"/></p:presentation>',
            "ppt/_rels/presentation.xml.rels": _rels(
                "slides/slide1.xml", f"{_REL}/slide"
            ),
            "ppt/slides/slide1.xml": f'{_XML}<p:sld xmlns:p="{p}" xmlns:a="{a}">'
            f"{tree}</p:sld>",
        },
        when,
    )


# ------------------------------------------------------------ images, text


def _image(lines: list[str], fmt: str) -> bytes:
    """A light 'scanned page' with grey text bars (no metadata)."""
    from PIL import Image, ImageDraw

    im = Image.new("RGB", (1240, 1754), (246, 245, 241))
    draw = ImageDraw.Draw(im)
    y = 140
    for i, line in enumerate(lines[:30]):
        width = min(1040, 60 + 18 * len(line))
        draw.rectangle(
            (100, y, 100 + width, y + (34 if i == 0 else 18)), fill=(70, 70, 76)
        )
        y += 70 if i == 0 else 40
    out = io.BytesIO()
    if fmt == "PNG":
        im.save(out, format="PNG")
    else:
        im.save(out, format="JPEG", quality=85)
    return out.getvalue()


def _ics(lines: list[str], when: dt.datetime) -> bytes:
    utc = when.astimezone(dt.UTC)
    start = utc.strftime("%Y%m%dT%H%M%SZ")
    body = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Calendar//EN",
        "BEGIN:VEVENT",
        f"UID:{start}-{hashlib.sha256(chr(10).join(lines).encode()).hexdigest()[:12]}",
        f"DTSTAMP:{start}",
        f"DTSTART:{start}",
        f"SUMMARY:{lines[0] if lines else ''}",
        "END:VEVENT",
        "END:VCALENDAR",
    ]
    return ("\r\n".join(body) + "\r\n").encode("utf-8")


def _vcf(lines: list[str]) -> bytes:
    name = lines[0] if lines else ""
    body = ["BEGIN:VCARD", "VERSION:3.0", f"FN:{name}", "END:VCARD"]
    return ("\r\n".join(body) + "\r\n").encode("utf-8")
