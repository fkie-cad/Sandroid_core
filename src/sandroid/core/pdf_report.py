"""PDF forensic report.

Originally adapted from https://github.com/jurasec/python-reportlab-example.

All inputs are derived from the result folder (the results JSON and
``raw/screenshots``); no environment variables or working-directory relative
paths are involved, so a report can be (re)generated from any finished result
folder via :func:`generate_pdf_report`. Logos are loaded from the installed
package (``sandroid/assets``). Evidence files are never modified.
"""

from __future__ import annotations

import io
import json
import logging
import os
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.colors import Color
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    CondPageBreak,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from . import timeline_generator
from .run_report import (
    DEFAULT_PDF_NAME,
    DEFAULT_RESULTS_NAME,
    RUN_METADATA_KEY,
    iso_now,
    plain_text,
    sanitize_results,
    sha256_file,
)

logger = logging.getLogger(__name__)

#: Maximum diff lines shown per changed file (table cells cannot split
#: across pages); the complete diff is always in the results JSON.
MAX_DIFF_LINES = 40

#: Page geometry.
MARGIN_X = 50
MARGIN_TOP = 75
MARGIN_BOTTOM = 70
FRAME_WIDTH = A4[0] - 2 * MARGIN_X

#: Keys in the results JSON that are not artefact lists.
_NON_ARTEFACT_KEYS = {
    "Device Name",
    "Emulator relative action timestamp",
    "Action Duration",
    "Other Data",
    RUN_METADATA_KEY,
}

_SCREENSHOT_EXTS = (".png", ".jpg", ".jpeg")


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


@cache
def _asset_bytes(name: str) -> bytes:
    """Return the bytes of a packaged asset (``sandroid/assets/<name>``)."""
    return resources.files("sandroid").joinpath("assets", name).read_bytes()


def asset_image_reader(name: str) -> ImageReader:
    """ImageReader for a packaged asset, independent of the working directory."""
    return ImageReader(io.BytesIO(_asset_bytes(name)))


FRAUNHOFER_LOGO = "Fraunhofer_Logo.jpg"
SANDROID_LOGO = "sandroid_logo.png"


# ---------------------------------------------------------------------------
# Canvas with header logos and "Page x of y" footer
# ---------------------------------------------------------------------------


def _make_canvas_class(footer_text: str):
    class _FooterCanvas(FooterCanvas):
        footer_left = footer_text

    return _FooterCanvas


class FooterCanvas(canvas.Canvas):
    """Canvas that draws the logos and a ``Page x of y`` footer."""

    footer_left = ""

    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self.pages = []
        self.width, self.height = A4

    def showPage(self):
        self.pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_count = len(self.pages)
        for page in self.pages:
            self.__dict__.update(page)
            if self._pageNumber > 1:
                self.draw_canvas(page_count)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_canvas(self, page_count):
        page = f"Page {self._pageNumber} of {page_count}"
        self.saveState()
        self.drawImage(
            asset_image_reader(FRAUNHOFER_LOGO),
            MARGIN_X,
            self.height - 50,
            width=100,
            height=20,
            preserveAspectRatio=True,
            anchor="w",
        )
        self.drawImage(
            asset_image_reader(SANDROID_LOGO),
            self.width - MARGIN_X - 100,
            self.height - 50,
            width=100,
            height=20,
            preserveAspectRatio=True,
            anchor="e",
            mask="auto",
        )
        self.setStrokeColorRGB(0, 0, 0)
        self.setLineWidth(0.5)
        self.line(MARGIN_X, 58, A4[0] - MARGIN_X, 58)
        self.setFont("Helvetica", 7.5)
        self.setFillColorRGB(0.3, 0.3, 0.3)
        if self.footer_left:
            self.drawString(MARGIN_X, 45, self.footer_left)
        self.drawRightString(A4[0] - MARGIN_X, 45, page)
        self.restoreState()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _txt(value: Any) -> str:
    """Plain, XML-escaped text for a Paragraph."""
    if value is None:
        return "–"
    return escape(plain_text(str(value)))


def find_results_json(result_dir: str | os.PathLike[str]) -> Path:
    """Locate the results JSON inside a result folder.

    Prefers ``sandroid.json``; otherwise the newest top-level ``*.json`` that
    looks like a Sandroid result (has a ``"Device Name"`` key).

    Raises:
        FileNotFoundError: If no results JSON is found.
    """
    root = Path(result_dir)
    preferred = root / DEFAULT_RESULTS_NAME
    if preferred.is_file():
        return preferred
    candidates = sorted(
        root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    for cand in candidates:
        try:
            data = json.loads(cand.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and "Device Name" in data:
            return cand
    raise FileNotFoundError(f"No Sandroid results JSON found in {root}")


def find_screenshot_dir(result_dir: str | os.PathLike[str]) -> Path | None:
    """Return the screenshot folder of a result folder, if it has images."""
    root = Path(result_dir)
    for cand in (root / "raw" / "screenshots", root / "screenshots"):
        if cand.is_dir() and any(
            p.suffix.lower() in _SCREENSHOT_EXTS for p in cand.iterdir()
        ):
            return cand
    return None


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


class PDFReport:
    """Render a results JSON into a PDF report.

    Args:
        path: Output PDF path.
        result_file_to_parse: Results JSON path.
        results_dir: The result folder (screenshots, timeline image). Defaults
            to the folder that contains the JSON file.
    """

    data = None
    inputFileName = ""

    def __init__(self, path, result_file_to_parse, results_dir=None):
        self.inputFileName = str(result_file_to_parse)
        try:
            with open(self.inputFileName, "rb") as inputFile:
                self.data = sanitize_results(json.loads(inputFile.read()))
        except OSError as e:
            logger.error(f"Failed to open input file '{self.inputFileName}': {e}")
            raise

        self.path = str(path)
        self.results_dir = Path(
            results_dir
            if results_dir is not None
            else Path(self.inputFileName).resolve().parent
        )
        self.meta: dict[str, Any] = self.data.get(RUN_METADATA_KEY) or {}
        self.other: dict[str, Any] = self.data.get("Other Data") or {}
        self.input_sha256 = sha256_file(self.inputFileName)
        self.generated_at = iso_now()
        self.elements: list[Any] = []

        self.header_font_color = Color(12 / 255, 154 / 255, 124 / 255, 1)
        self.highlight_color = Color(255 / 255, 111 / 255, 89 / 255, 1)
        self.small_title_font_color = self.header_font_color
        self.table_line_color = Color(0.82, 0.82, 0.82, 1)
        self.table_header_background_color = Color(31 / 255, 32 / 255, 65 / 255, 1)
        self.zebra = Color(0.96, 0.97, 0.97, 1)
        self.white = Color(1, 1, 1, 1)
        self._init_styles()

        self.firstPage()
        self.summaryTableMaker()
        self.settingsTableMaker()
        if self.data.get("Changed Files") or self.data.get("New Files"):
            self.timelinePage()
        self.pageHeader("Detailed Report")
        for key, title in (
            ("Changed Files", "Changed Files"),
            ("New Files", "New Files"),
            ("Deleted Files", "Deleted Files"),
            ("Processes", "Processes"),
            ("Listening Sockets", "Listening Sockets"),
            ("Network", "Network (DNS names)"),
            ("Network IP:Port (send/recv)", "Network IP:Port (send/recv)"),
        ):
            if key not in self.data:
                continue
            if key == "Changed Files":
                self.changedFilesTableMaker()
            else:
                self.generalTableMaker(key, title)
        if "APK Hashes" in self.other:
            self.APKTableMaker()
        if "Artifact Hashes" in self.other:
            self.newFileHashesTableMaker()
            self.changedFileHashesTableMaker()

        screenshot_dir = find_screenshot_dir(self.results_dir)
        if screenshot_dir is not None:
            self.elements.append(PageBreak())
            self.sectionTitle("Screenshots")
            self.image_grid(screenshot_dir)

        device = self.data.get("Device Name", "")
        version = (self.meta.get("host") or {}).get("sandroid_version") or _version()
        self.doc = SimpleDocTemplate(
            self.path,
            pagesize=A4,
            leftMargin=MARGIN_X,
            rightMargin=MARGIN_X,
            topMargin=MARGIN_TOP,
            bottomMargin=MARGIN_BOTTOM,
            title=f"Sandroid Forensic Report – {device}",
            author="Sandroid (Fraunhofer FKIE)",
            subject=f"Results file SHA-256 {self.input_sha256}",
            creator=f"Sandroid {version}",
        )
        footer = f"Sandroid {version} · {device} · generated {self.generated_at}"
        self.doc.multiBuild(self.elements, canvasmaker=_make_canvas_class(footer))

    # ---- styles -----------------------------------------------------------

    def _init_styles(self):
        self.body = ParagraphStyle(
            "body", fontName="Helvetica", fontSize=7.5, leading=9.5
        )
        self.body_wrap = ParagraphStyle(
            "body_wrap", parent=self.body, wordWrap="CJK"
        )
        self.mono = ParagraphStyle(
            "mono", fontName="Courier", fontSize=6, leading=8, wordWrap="CJK"
        )
        self.center = ParagraphStyle("center", parent=self.body, alignment=TA_CENTER)
        self.header_cell = ParagraphStyle(
            "header_cell",
            parent=self.body,
            fontName="Helvetica-Bold",
            textColor=self.white,
            alignment=TA_LEFT,
        )
        self.section_style = ParagraphStyle(
            "section",
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=self.small_title_font_color,
            spaceAfter=6,
        )
        self.note_style = ParagraphStyle(
            "note",
            parent=self.body,
            fontName="Helvetica-Oblique",
            textColor=colors.HexColor("#555555"),
        )

    def _table_style(self, header=True, zebra=True):
        cmds = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, self.table_line_color),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]
        if header:
            cmds.append(
                ("BACKGROUND", (0, 0), (-1, 0), self.table_header_background_color)
            )
        if zebra:
            cmds.append(
                (
                    "ROWBACKGROUNDS",
                    (0, 1 if header else 0),
                    (-1, -1),
                    [self.white, self.zebra],
                )
            )
        return TableStyle(cmds)

    def _table(self, rows, col_widths, header=True):
        table = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
        table.setStyle(self._table_style(header=header))
        return table

    def sectionTitle(self, text):
        self.elements.append(CondPageBreak(4 * inch))
        self.elements.append(Paragraph(_txt(text), self.section_style))

    def note(self, text):
        self.elements.append(Paragraph(text, self.note_style))

    # ---- title page -------------------------------------------------------

    def firstPage(self):
        logos = Table(
            [
                [
                    Image(io.BytesIO(_asset_bytes(FRAUNHOFER_LOGO)), 0.6 * inch, 0.6 * inch),
                    Image(io.BytesIO(_asset_bytes(SANDROID_LOGO)), 1.1 * inch, 1.1 * inch),
                ]
            ],
            colWidths=[FRAME_WIDTH / 2, FRAME_WIDTH / 2],
        )
        logos.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (0, 0), "LEFT"),
                    ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        self.elements.append(logos)
        self.elements.append(Spacer(10, 18))
        title_style = ParagraphStyle(
            "title",
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=30,
            alignment=TA_LEFT,
            textColor=self.table_header_background_color,
        )
        sub_style = ParagraphStyle(
            "subtitle",
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#444444"),
        )
        self.elements.append(Paragraph("Sandroid Forensic Report", title_style))
        self.elements.append(
            Paragraph(
                "Automated forensic analysis of an Android Virtual Device",
                sub_style,
            )
        )
        self.elements.append(Spacer(10, 14))
        self.elements.append(Paragraph("Run metadata", self.section_style))

        md = self.meta
        host = md.get("host") or {}
        dev = md.get("device") or {}
        tools = host.get("tool_versions") or {}
        tool_str = ", ".join(f"{k} {v}" for k, v in tools.items() if v) or None
        android = dev.get("android_version")
        if android and dev.get("api_level") is not None:
            android = f"{android} (API level {dev.get('api_level')})"
        rows = [
            ("Report generated", self.generated_at),
            ("Analysis started", md.get("started_at")),
            ("Analysis ended", md.get("ended_at")),
            ("Action duration", f"{self.data.get('Action Duration', '–')} s"),
            (
                "Emulator action timestamp",
                self.data.get("Emulator relative action timestamp"),
            ),
            ("Run ID / mode", " / ".join(str(x) for x in (md.get("run_id"), md.get("mode")) if x) or None),
            ("Device name", self.data.get("Device Name")),
            ("Device serial", dev.get("serial")),
            ("AVD name", dev.get("avd_name")),
            ("Device model", dev.get("model")),
            ("Android version", android),
            ("Security patch level", dev.get("security_patch")),
            ("Build fingerprint", dev.get("build_fingerprint")),
            ("Sandroid version", host.get("sandroid_version")),
            ("Host OS", host.get("host_os")),
            ("Host name", host.get("host_name")),
            (
                "Python",
                " ".join(
                    x
                    for x in (
                        host.get("python_implementation"),
                        host.get("python_version"),
                    )
                    if x
                )
                or None,
            ),
            ("Tool versions", tool_str),
            ("Results file", os.path.basename(self.inputFileName)),
            ("Results file SHA-256", self.input_sha256),
        ]
        table_rows = []
        for key, value in rows:
            style = self.mono if key in ("Build fingerprint", "Results file SHA-256") else self.body_wrap
            table_rows.append(
                [Paragraph(f"<b>{_txt(key)}</b>", self.body), Paragraph(_txt(value), style)]
            )
        table = Table(table_rows, colWidths=[130, FRAME_WIDTH - 130])
        table.setStyle(self._table_style(header=False))
        self.elements.append(table)
        self.elements.append(Spacer(10, 10))
        if not md:
            self.note(
                "Run metadata (timestamps, device build, tool versions) was not "
                "recorded in this results file; it was produced by an older "
                "Sandroid version. Values shown as “–” are unknown."
            )
        self.note(
            "File hashes are given as SHA-256 (MD5 retained for compatibility). "
            "A manifest of all files in the result folder (manifest.json, "
            "SHA256SUMS) is written at the end of each run; its SHA-256 is "
            "recorded in the Sandroid log. Diff excerpts in this report may be "
            "shortened; the complete data is in the results file."
        )
        self.elements.append(PageBreak())

    # ---- summary / settings -----------------------------------------------

    def pageHeader(self, content):
        self.elements.append(CondPageBreak(4 * inch))
        style = ParagraphStyle(
            "pageheader",
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=22,
            textColor=self.header_font_color,
            spaceBefore=6,
            spaceAfter=10,
        )
        self.elements.append(Paragraph(_txt(content), style))

    def summaryTableMaker(self):
        self.sectionTitle("Summary")
        rows = []
        total = 0
        for section, value in self.data.items():
            if section in _NON_ARTEFACT_KEYS:
                continue
            count = len(value) if isinstance(value, (list, dict)) else 0
            rows.append([section, count])
            total += count
        hashes = self._artifact_hashes()
        if hashes is not None:
            n_new = len(hashes.get("new_file_hashes") or {})
            n_changed = len(hashes.get("changed_file_hashes(old,new)") or {})
            rows.append(["Hashes of files created during action", n_new])
            rows.append(["Before/after hashes of changed files", n_changed])
            total += n_new + n_changed
        apks = self._list_other("APK Hashes")
        if apks is not None:
            rows.append(["APK hashes", len(apks)])
            total += len(apks)
        rows.append(["Total number of artifacts found", total])
        data = [
            [Paragraph(_txt(a), self.body), Paragraph(_txt(b), self.body)]
            for a, b in rows
        ]
        table = Table(data, colWidths=[FRAME_WIDTH - 80, 80])
        style = self._table_style(header=False)
        style.add("ALIGN", (1, 0), (1, -1), "RIGHT")
        style.add("BACKGROUND", (0, -1), (-1, -1), self.highlight_color)
        table.setStyle(style)
        self.elements.append(table)
        self.elements.append(Spacer(10, 16))

    def settingsTableMaker(self):
        settings = self.meta.get("settings") or {}
        if not settings:
            return
        self.sectionTitle("Analysis settings")
        rows = [self.make_header(["Setting", "Value"])]
        for key, value in _flatten(settings):
            rows.append(
                [Paragraph(_txt(key), self.body_wrap), Paragraph(_txt(value), self.body_wrap)]
            )
        self.elements.append(self._table(rows, [200, FRAME_WIDTH - 200]))
        self.elements.append(PageBreak())

    # ---- timeline ---------------------------------------------------------

    def timelinePage(self):
        png = self.results_dir / "timeline.png"
        try:
            produced = timeline_generator.parse_timeline(self.inputFileName, str(png))
        except Exception as exc:
            logger.warning("Timeline could not be generated: %s", exc)
            produced = None
        if not produced:
            return
        self.elements.append(CondPageBreak(9 * inch))
        self.elements.append(Paragraph("Timeline", self.section_style))
        self.note(
            "Changed (left) and newly created (right) files by seconds after the "
            "start of the recorded action, as observed by the file-system "
            "timestamp collector."
        )
        with PILImage.open(produced) as im:
            w, h = im.size
        max_w, max_h = FRAME_WIDTH, A4[1] - MARGIN_TOP - MARGIN_BOTTOM - 90
        scale = min(max_w / w, max_h / h)
        self.elements.append(Image(produced, width=w * scale, height=h * scale))

    # ---- artefact tables --------------------------------------------------

    def generalTableMaker(self, json_section_to_tableize, title=None):
        self.sectionTitle(title or json_section_to_tableize)
        entries = self.data.get(json_section_to_tableize) or []
        if not entries:
            self.note("No entries.")
            self.elements.append(Spacer(10, 12))
            return
        rows = [self.make_header(["No.", "Entry"])]
        for num, entry in enumerate(entries, 1):
            rows.append(
                [Paragraph(str(num), self.body), Paragraph(_txt(entry), self.body_wrap)]
            )
        self.elements.append(self._table(rows, [30, FRAME_WIDTH - 30]))
        self.elements.append(Spacer(10, 14))

    def changedFilesTableMaker(self):
        self.sectionTitle("Changed Files")
        entries = self.data.get("Changed Files") or []
        if not entries:
            self.note("No entries.")
            self.elements.append(Spacer(10, 12))
            return
        rows = [self.make_header(["No.", "File", "Changes"])]
        for num, item in enumerate(entries, 1):
            if isinstance(item, dict) and item:
                file_name = next(iter(item))
                changes = item[file_name]
            else:
                file_name, changes = item, []
            if isinstance(changes, str):
                changes = [changes]
            lines: list[str] = []
            for block in changes or []:
                lines.extend(str(block).strip("\n").splitlines())
            lines = [ln.strip() for ln in lines if ln.strip()]
            shown = lines[:MAX_DIFF_LINES]
            text = "<br/>".join(_txt(ln) for ln in shown)
            if len(lines) > MAX_DIFF_LINES:
                text += (
                    f"<br/><i>… {len(lines) - MAX_DIFF_LINES} more line(s), "
                    "see results file</i>"
                )
            rows.append(
                [
                    Paragraph(str(num), self.body),
                    Paragraph(_txt(file_name), self.body_wrap),
                    Paragraph(text, self.body_wrap),
                ]
            )
        self.elements.append(self._table(rows, [30, 190, FRAME_WIDTH - 220]))
        self.elements.append(Spacer(10, 14))

    def APKTableMaker(self):
        apks = self._list_other("APK Hashes") or []
        sha_map = _parse_pkg_hashes(self._list_other("APK Hashes SHA-256") or [])
        self.sectionTitle("APKs & Hashes")
        if not apks:
            self.note("No entries.")
            return
        rows = [self.make_header(["No.", "Package", "Hashes"])]
        for num, (pkg, md5) in enumerate(_parse_pkg_hashes(apks).items(), 1):
            rows.append(
                [
                    Paragraph(str(num), self.body),
                    Paragraph(_txt(pkg), self.body_wrap),
                    self._hash_cell(sha_map.get(pkg), md5),
                ]
            )
        self.elements.append(self._table(rows, [30, 175, FRAME_WIDTH - 205]))
        self.elements.append(Spacer(10, 14))

    def newFileHashesTableMaker(self):
        hashes = self._artifact_hashes() or {}
        md5s = hashes.get("new_file_hashes") or {}
        shas = hashes.get("new_file_hashes_sha256") or {}
        self.sectionTitle("Hashes of new files")
        if not md5s and not shas:
            self.note("No entries.")
            self.elements.append(Spacer(10, 12))
            return
        rows = [self.make_header(["No.", "File", "Hashes"])]
        for num, name in enumerate(sorted(set(md5s) | set(shas)), 1):
            rows.append(
                [
                    Paragraph(str(num), self.body),
                    Paragraph(_txt(name), self.body_wrap),
                    self._hash_cell(shas.get(name), md5s.get(name)),
                ]
            )
        self.elements.append(self._table(rows, [30, 175, FRAME_WIDTH - 205]))
        self.elements.append(Spacer(10, 14))

    def changedFileHashesTableMaker(self):
        hashes = self._artifact_hashes() or {}
        md5s = hashes.get("changed_file_hashes(old,new)") or {}
        shas = hashes.get("changed_file_hashes_sha256(old,new)") or {}
        self.sectionTitle("Hashes of changed files (before / after action)")
        if not md5s and not shas:
            self.note("No entries.")
            self.elements.append(Spacer(10, 12))
            return
        rows = [self.make_header(["No.", "File", "Before action", "After action"])]
        width = (FRAME_WIDTH - 25 - 120) / 2
        for num, name in enumerate(sorted(set(md5s) | set(shas)), 1):
            md5_pair = list(md5s.get(name) or [None, None]) + [None, None]
            sha_pair = list(shas.get(name) or [None, None]) + [None, None]
            rows.append(
                [
                    Paragraph(str(num), self.body),
                    Paragraph(_txt(name), self.body_wrap),
                    self._hash_cell(sha_pair[0], md5_pair[0]),
                    self._hash_cell(sha_pair[1], md5_pair[1]),
                ]
            )
        self.elements.append(self._table(rows, [25, 120, width, width]))
        self.elements.append(Spacer(10, 14))

    # ---- screenshots ------------------------------------------------------

    def image_grid(self, img_dir=None):
        """Lay out screenshots in a 4-column grid (files are not modified)."""
        img_dir = Path(img_dir) if img_dir is not None else find_screenshot_dir(
            self.results_dir
        )
        if img_dir is None:
            return
        files = sorted(
            p for p in img_dir.iterdir() if p.suffix.lower() in _SCREENSHOT_EXTS
        )
        per_row = 4
        cell_w = FRAME_WIDTH / per_row - 6
        cells = []
        for path in files:
            try:
                with PILImage.open(path) as im:
                    w, h = im.size
            except Exception as exc:
                logger.warning("Skipping unreadable screenshot %s: %s", path, exc)
                continue
            scale = min(cell_w / w, (2.6 * inch) / h)
            cells.append(
                [
                    Image(str(path), width=w * scale, height=h * scale),
                    Paragraph(_txt(path.name), ParagraphStyle(
                        "cap", parent=self.body, fontSize=6, alignment=TA_CENTER,
                        wordWrap="CJK")),
                ]
            )
        rows = []
        for i in range(0, len(cells), per_row):
            chunk = cells[i : i + per_row]
            chunk += [""] * (per_row - len(chunk))
            rows.append(chunk)
        if rows:
            table = Table(rows, colWidths=[FRAME_WIDTH / per_row] * per_row)
            table.setStyle(
                TableStyle(
                    [
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            self.elements.append(table)

    # ---- small helpers ----------------------------------------------------

    def _hash_cell(self, sha256, md5):
        parts = []
        if sha256:
            parts.append(f"SHA-256: {_txt(sha256)}")
        if md5:
            parts.append(f"MD5: {_txt(md5)}")
        return Paragraph("<br/>".join(parts) or "n/a", self.mono)

    def _list_other(self, key):
        value = self.other.get(key)
        if value is None:
            return None
        if isinstance(value, list) and value and isinstance(value[0], list):
            merged = []
            for sub in value:
                merged.extend(sub)
            return merged
        return value if isinstance(value, list) else [value]

    def _artifact_hashes(self):
        value = self.other.get("Artifact Hashes")
        if isinstance(value, list):
            value = value[-1] if value else None
        return value if isinstance(value, dict) else None

    def make_header(self, header_array):
        return [Paragraph(f"<b>{_txt(t)}</b>", self.header_cell) for t in header_array]

    def draw_panel(self, *args, **kwargs):  # pragma: no cover - legacy no-op
        """Unused legacy helper kept for API compatibility."""


def _parse_pkg_hashes(entries) -> dict[str, str]:
    out: dict[str, str] = {}
    for row in entries:
        pkg, sep, digest = str(row).partition(": ")
        out[pkg] = digest if sep else ""
    return out


def _flatten(value, prefix=""):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(value, list):
        yield prefix, ", ".join(str(v) for v in value) if value else "[]"
    else:
        yield prefix, value


def _version() -> str:
    from sandroid._version import __version__

    return __version__


def generate_pdf_report(
    result_dir: str | os.PathLike[str],
    json_file: str | os.PathLike[str] | None = None,
    output_pdf: str | os.PathLike[str] | None = None,
) -> Path:
    """Render the PDF report for a finished result folder.

    Args:
        result_dir: The run's result folder.
        json_file: Results JSON; located with :func:`find_results_json` if
            omitted.
        output_pdf: Output path; defaults to
            ``<result_dir>/Sandroid_Forensic_Report.pdf``.

    Returns:
        Path of the written PDF.
    """
    root = Path(result_dir)
    json_path = Path(json_file) if json_file else find_results_json(root)
    out = Path(output_pdf) if output_pdf else root / DEFAULT_PDF_NAME
    PDFReport(str(out), str(json_path), results_dir=root)
    logger.info(
        "PDF report generated: %s (SHA-256 %s)", out, sha256_file(out)
    )
    return out


__all__ = ["PDFReport", "find_results_json", "generate_pdf_report"]


if __name__ == "__main__":  # pragma: no cover
    import sys

    print(generate_pdf_report(sys.argv[1] if len(sys.argv) > 1 else "."))
