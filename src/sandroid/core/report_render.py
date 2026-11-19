"""Render a ``report.json`` document as PDF (ReportLab) and Markdown.

Both renderers take only the report document (as written to ``report.json``)
and the folder it lives in (``base_dir``, against which relative image paths
resolve). They never read the timeline. Every screenshot is checked against
its recorded SHA-256 before it is shown; a missing or changed file becomes a
visible warning instead of an image.

The PDF keeps the layout rules of the former PDF report module: package
logos, a ``Page x of y`` footer, table cells bounded to fit on a page, long
diffs continued over several rows, and per-section isolation (a section that
cannot be built or laid out is replaced by a note).
"""

from __future__ import annotations

import io
import logging
import os
from collections.abc import Mapping
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
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.doctemplate import LayoutError

from .run_report import plain_text, sha256_file

logger = logging.getLogger(__name__)

#: Maximum diff lines shown in one table cell (table cells cannot split
#: across pages); longer diffs continue in additional rows.
MAX_DIFF_LINES = 40
#: Maximum lines shown per list cell over all continuation rows.
MAX_DIFF_LINES_TOTAL = 200
#: Maximum characters shown per diff line / per plain table entry.
MAX_LINE_CHARS = 400
MAX_ENTRY_CHARS = 2000
#: Maximum rendered height (pt) of a single table cell (frame is ~685 pt).
MAX_CELL_HEIGHT = 480.0
#: Target height (pt) of one continuation row of a long diff.
DIFF_CHUNK_HEIGHT = 240.0
#: Default cell padding of a ReportLab table (left + right).
_CELL_HPAD = 12

MARGIN_X = 50
MARGIN_TOP = 75
MARGIN_BOTTOM = 70
FRAME_WIDTH = A4[0] - 2 * MARGIN_X

#: Stand-alone screenshots per row and their maximum height.
SHOTS_PER_ROW = 4
SHOT_MAX_HEIGHT = 2.4 * inch
#: Thumbnails next to a transcript step: column width, per row, max height.
THUMB_COL = 174.0
THUMBS_PER_ROW = 3
THUMB_MAX_HEIGHT = 1.5 * inch

FRAUNHOFER_LOGO = "Fraunhofer_Logo.jpg"
SANDROID_LOGO = "sandroid_logo.png"

DEFAULT_TITLE = "Sandroid Forensic Report"


# ---------------------------------------------------------------------------
# Assets and canvas
# ---------------------------------------------------------------------------


@cache
def _asset_bytes(name: str) -> bytes:
    """Return the bytes of a packaged asset (``sandroid/assets/<name>``)."""
    return resources.files("sandroid").joinpath("assets", name).read_bytes()


def asset_image_reader(name: str) -> ImageReader:
    """ImageReader for a packaged asset, independent of the working directory."""
    return ImageReader(io.BytesIO(_asset_bytes(name)))


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


def _make_canvas_class(footer_text: str):
    class _FooterCanvas(FooterCanvas):
        footer_left = footer_text

    return _FooterCanvas


# ---------------------------------------------------------------------------
# Text helpers (shared)
# ---------------------------------------------------------------------------


def _txt(value: Any) -> str:
    """Plain, XML-escaped text for a Paragraph."""
    if value is None:
        return "–"
    return escape(plain_text(str(value)))


def _clip(text: str, limit: int) -> str:
    """Shorten ``text`` to ``limit`` characters with an explicit marker."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]} … [{len(text) - limit} more characters]"


def bounded_lines_paragraph(
    lines: list[str],
    style: ParagraphStyle,
    width: float,
    *,
    max_lines: int = MAX_DIFF_LINES,
    max_line_chars: int = MAX_LINE_CHARS,
    max_height: float = MAX_CELL_HEIGHT,
    see_also: str = "the results file",
) -> Paragraph:
    """Paragraph for a table cell whose height never exceeds ``max_height``.

    Long lines are clipped to ``max_line_chars``; at most ``max_lines`` lines
    are shown, fewer if the wrapped text would still be too tall. Omitted
    lines are stated explicitly ("… N more line(s) not shown — see …").
    """
    clipped = [_clip(plain_text(str(ln)), max_line_chars) for ln in lines]
    shown = min(len(clipped), max_lines)
    while True:
        text = "<br/>".join(escape(ln) for ln in clipped[:shown])
        omitted = len(clipped) - shown
        if omitted:
            note = f"<i>… {omitted} more line(s) not shown — see {escape(see_also)}</i>"
            text = f"{text}<br/>{note}" if text else note
        para = Paragraph(text, style)
        _w, height = para.wrap(width, 1e9)
        if height <= max_height or shown == 0:
            return para
        shown = max(0, min(shown - 1, int(shown * max_height / height)))


def split_lines_into_cells(
    lines: list[str],
    style: ParagraphStyle,
    width: float,
    *,
    max_total: int = MAX_DIFF_LINES_TOTAL,
    max_lines: int = MAX_DIFF_LINES,
    max_line_chars: int = MAX_LINE_CHARS,
    max_height: float = MAX_CELL_HEIGHT,
    chunk_height: float = DIFF_CHUNK_HEIGHT,
    see_also: str = "the results file",
) -> list[Paragraph]:
    """Distribute ``lines`` over several cells that each fit on a page."""
    clipped = [_clip(plain_text(str(ln)), max_line_chars) for ln in lines]
    shown, rest = clipped[:max_total], clipped[max_total:]
    chunks: list[list[str]] = []
    current: list[str] = []
    height = 0.0
    for ln in shown:
        _w, h = Paragraph(escape(ln), style).wrap(width, 1e9)
        if current and (height + h > chunk_height or len(current) >= max_lines):
            chunks.append(current)
            current, height = [], 0.0
        current.append(ln)
        height += h
    if current or not chunks:
        chunks.append(current)
    cells = [
        bounded_lines_paragraph(
            chunk,
            style,
            width,
            max_lines=max_lines,
            max_line_chars=max_line_chars + 40,
            max_height=max_height,
            see_also=see_also,
        )
        for chunk in chunks
    ]
    if rest:
        note = f"<i>… {len(rest)} more line(s) not shown — see {escape(see_also)}</i>"
        cells.append(Paragraph(note, style))
    return cells


def _clock(value: Any, *, ms: bool = False) -> str:
    from .report_engine import _clock as clock

    return clock(value, ms=ms)


class ImageCheck:
    """Resolves image blocks and verifies their SHA-256 (cached per file)."""

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self._hashes: dict[Path, str | None] = {}

    def resolve(self, block: Mapping[str, Any]) -> tuple[Path | None, str | None]:
        """``(path, None)`` for a verified image, else ``(None, warning)``."""
        caption = block.get("caption") or f"screenshot #{block.get('seq')}"
        if block.get("error"):
            return None, f"Screenshot {caption} was not taken: {block['error']}"
        raw = block.get("path")
        if not raw:
            return None, f"Screenshot {caption} has no file."
        path = Path(str(raw))
        if not path.is_absolute():
            path = self.base_dir / path
        if path not in self._hashes:
            try:
                self._hashes[path] = sha256_file(path) if path.is_file() else None
            except OSError:
                self._hashes[path] = None
        actual = self._hashes[path]
        if actual is None:
            return None, f"Screenshot {caption} is missing: {raw}"
        expected = str(block.get("sha256") or "").lower()
        if expected and actual != expected:
            return None, (
                f"Screenshot {caption} ({raw}) does not match its recorded "
                f"SHA-256 {expected}; it is not shown."
            )
        return path, None


# ---------------------------------------------------------------------------
# Step descriptions (shared by PDF and Markdown)
# ---------------------------------------------------------------------------


def step_title(step: Mapping[str, Any]) -> str:
    """One-line description of a transcript step (plain text)."""
    src, kind = step.get("src"), step.get("kind")
    if src == "screen":
        screen = step.get("screen") or {}
        where = "/".join(x for x in (screen.get("pkg"), screen.get("cls")) if x)
        title = f" '{screen['title']}'" if screen.get("title") else ""
        return f"Screen → {where or step.get('summary') or '?'}{title}"
    if src == "shot":
        return "Manual screenshot"
    if src == "label":
        return f"Mark {step.get('mark')} '{step.get('element') or ''}'"
    element = step.get("element")
    if not element:
        return str(step.get("summary") or kind)
    text = f"'{element}'"
    cls = step.get("element_class")
    if cls and cls != element:
        text += f" ({cls})"
    xy = step.get("xy")
    if xy:
        text += f" at ({xy[0]}, {xy[1]})"
    if step.get("to_xy"):
        text += f" → ({step['to_xy'][0]}, {step['to_xy'][1]})"
    if kind == "text":
        text = f"into {text}"
    return text


def effect_lines(step: Mapping[str, Any]) -> list[str]:
    """Plain-text effect summaries of a step (files, network, profile values)."""
    effects = step.get("effects") or {}
    out: list[str] = []
    files = effects.get("files")
    if files:
        kinds = ", ".join(
            f"{k} {n}" for k, n in sorted(files.get("by_kind", {}).items())
        )
        items = "; ".join(
            f"{i['path']}"
            + (f" ×{i['n']}" if i.get("n", 1) > 1 else "")
            + " (#"
            + ", #".join(str(s) for s in i.get("seqs") or [])
            + ")"
            for i in files.get("top") or []
        )
        more = files.get("paths", 0) - len(files.get("top") or [])
        out.append(
            f"Files (app): {files.get('count')} event(s) ({kinds}): {items}"
            + (f"; … {more} more path(s)" if more > 0 else "")
        )
    net = effects.get("net")
    if net:
        items = "; ".join(
            (
                f"{f.get('method') or ''} {f.get('status') or ''} "
                f"{f.get('host') or ''}{f.get('path') or ''}".strip()
                if f.get("kind") == "flow"
                else f"TLS failure {f.get('host') or ''} ({f.get('error') or '?'})"
            )
            + f" (#{f.get('seq')})"
            for f in net.get("top") or []
        )
        more = net.get("count", 0) - len(net.get("top") or [])
        out.append(
            f"Network: {net.get('count')} flow(s): {items}"
            + (f"; … {more} more" if more > 0 else "")
        )
    privacy = effects.get("privacy")
    if privacy:
        items = "; ".join(
            f"{p.get('label') or '?'} "
            + ("sent to" if p.get("kind") == "sent" else "stored in")
            + f" {p.get('to') or '?'}, {p.get('encoding') or 'as is'} (#{p.get('seq')})"
            for p in privacy.get("top") or []
        )
        more = privacy.get("count", 0) - len(privacy.get("top") or [])
        out.append(
            f"Profile values: {privacy.get('count')} finding(s): {items}"
            + (f"; … {more} more" if more > 0 else "")
        )
    return out


def _screen_text(screen: Mapping[str, Any] | None) -> str | None:
    if not screen:
        return None
    if screen.get("summary") and not screen.get("pkg"):
        return str(screen["summary"])
    where = "/".join(x for x in (screen.get("pkg"), screen.get("cls")) if x)
    if screen.get("title"):
        where += f" '{screen['title']}'"
    return where or None


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


class PdfRenderer:
    """Render a report document into a PDF.

    Attributes:
        story: The flowables of the last build.
        degraded_sections: ``[(section title, reason)]`` replaced by a note.
    """

    def __init__(self, doc: Mapping[str, Any], base_dir: Path):
        self.doc = doc
        self.base_dir = Path(base_dir)
        self.images = ImageCheck(self.base_dir)
        self.elements: list[Any] = []
        self.story: list[Any] = []
        self.degraded_sections: list[tuple[str, str]] = []
        self._builder_errors: list[tuple[str, str]] = []
        self.header_font_color = Color(12 / 255, 154 / 255, 124 / 255, 1)
        self.highlight_color = Color(255 / 255, 111 / 255, 89 / 255, 1)
        self.table_line_color = Color(0.82, 0.82, 0.82, 1)
        self.table_header_background_color = Color(31 / 255, 32 / 255, 65 / 255, 1)
        self.zebra = Color(0.96, 0.97, 0.97, 1)
        self.white = Color(1, 1, 1, 1)
        self._init_styles()

    # ---- styles -----------------------------------------------------------

    def _init_styles(self) -> None:
        self.body = ParagraphStyle(
            "body", fontName="Helvetica", fontSize=7.5, leading=9.5
        )
        self.body_wrap = ParagraphStyle("body_wrap", parent=self.body, wordWrap="CJK")
        self.mono = ParagraphStyle(
            "mono", fontName="Courier", fontSize=6, leading=8, wordWrap="CJK"
        )
        self.small = ParagraphStyle(
            "small",
            parent=self.body,
            fontSize=6.5,
            leading=8,
            textColor=colors.HexColor("#555555"),
            wordWrap="CJK",
        )
        self.caption = ParagraphStyle(
            "cap", parent=self.body, fontSize=6, alignment=TA_CENTER, wordWrap="CJK"
        )
        self.header_cell = ParagraphStyle(
            "header_cell",
            parent=self.body,
            fontName="Helvetica-Bold",
            textColor=self.white,
            alignment=TA_LEFT,
        )
        self.page_header = ParagraphStyle(
            "pageheader",
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=22,
            textColor=self.header_font_color,
            spaceBefore=6,
            spaceAfter=10,
        )
        self.headings = {
            2: ParagraphStyle(
                "h2",
                fontName="Helvetica-Bold",
                fontSize=12,
                leading=15,
                textColor=self.header_font_color,
                spaceBefore=6,
                spaceAfter=5,
            ),
            3: ParagraphStyle(
                "h3",
                fontName="Helvetica-Bold",
                fontSize=10,
                leading=13,
                textColor=self.table_header_background_color,
                spaceBefore=5,
                spaceAfter=3,
            ),
            4: ParagraphStyle(
                "h4",
                fontName="Helvetica-Bold",
                fontSize=9,
                leading=11,
                textColor=colors.HexColor("#333333"),
                spaceBefore=4,
                spaceAfter=2,
            ),
        }
        self.note_style = ParagraphStyle(
            "note",
            parent=self.body,
            fontName="Helvetica-Oblique",
            textColor=colors.HexColor("#555555"),
        )
        self.warn_style = ParagraphStyle(
            "warn",
            parent=self.body_wrap,
            textColor=colors.HexColor("#8A5300"),
        )
        self.error_style = ParagraphStyle(
            "error",
            parent=self.body_wrap,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#8B0000"),
        )

    def _table_style(self, header: bool = True, zebra: bool = True) -> TableStyle:
        cmds: list[tuple] = [
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

    def _table(self, rows, col_widths, header: bool = True) -> Table:
        table = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
        table.setStyle(self._table_style(header=header))
        return table

    def _header_row(self, columns) -> list[Paragraph]:
        return [Paragraph(f"<b>{_txt(c)}</b>", self.header_cell) for c in columns]

    # ---- story assembly ---------------------------------------------------

    def _sections(self) -> list[Mapping[str, Any]]:
        return [s for s in self.doc.get("sections") or [] if isinstance(s, Mapping)]

    def _units(self) -> list[tuple[tuple[int, int], str, bool, list]]:
        """Layout units: each section's intro, then one per level-2 heading.

        A unit is built and laid out in isolation, so a defect degrades only
        that unit (e.g. one result table), never the whole section.

        Returns:
            ``[((section no, unit no), title, is_section_start, blocks)]``.
        """
        units: list[tuple[tuple[int, int], str, bool, list]] = []
        for si, section in enumerate(self._sections()):
            title = str(section.get("title") or section.get("id") or "Section")
            current: list = []
            units.append(((si, 0), title, True, current))
            for block in section.get("blocks") or []:
                if (
                    isinstance(block, Mapping)
                    and block.get("type") == "heading"
                    and int(block.get("level") or 2) <= 2
                ):
                    current = [block]
                    units.append(
                        ((si, len(units)), str(block.get("text")), False, current)
                    )
                else:
                    current.append(block)
        return units

    def _render_unit(self, title: str, head: bool, blocks: list) -> list[Any]:
        """Build one unit's flowables in isolation (errors -> a note)."""
        saved = self.elements
        self.elements = []
        try:
            if head:
                self.elements.append(CondPageBreak(3 * inch))
                self.elements.append(Paragraph(_txt(title), self.page_header))
            for block in blocks:
                self._block(block)
            return self.elements
        except Exception as exc:
            logger.error(
                "PDF section %r could not be built: %s", title, exc, exc_info=True
            )
            reason = f"{type(exc).__name__}: {exc}"
            self._builder_errors.append((title, reason))
            return self._placeholder(title, reason, head=head)
        finally:
            self.elements = saved

    def _placeholder(self, title: str, reason: Any, *, head: bool = True) -> list[Any]:
        reason_text = _clip(str(reason).splitlines()[0] if str(reason) else "", 300)
        return [
            CondPageBreak(2 * inch),
            Paragraph(_txt(title), self.page_header if head else self.headings[2]),
            Paragraph(
                f"<b>This section could not be laid out in the PDF</b> "
                f"({_txt(reason_text)}). The complete data is in report.json and "
                "the results file of this folder.",
                self.note_style,
            ),
            Spacer(10, 12),
        ]

    def _cover(self) -> list[Any]:
        logos = Table(
            [
                [
                    Image(
                        io.BytesIO(_asset_bytes(FRAUNHOFER_LOGO)),
                        0.6 * inch,
                        0.6 * inch,
                    ),
                    Image(
                        io.BytesIO(_asset_bytes(SANDROID_LOGO)), 1.1 * inch, 1.1 * inch
                    ),
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
        scope = self.doc.get("scope") or {}
        what = (
            f"Run {scope.get('run_id')}"
            if scope.get("kind") == "run"
            else "Session timeline"
        )
        return [
            logos,
            Spacer(10, 18),
            Paragraph(_txt(self.doc.get("title") or DEFAULT_TITLE), title_style),
            Paragraph(
                f"Automated forensic analysis of an Android device · {_txt(what)}",
                sub_style,
            ),
            Spacer(10, 14),
        ]

    def _story(self, skip: dict[tuple[int, int], str]) -> list[Any]:
        story = self._cover()
        for key, title, head, blocks in self._units():
            if key in skip:
                story.extend(self._placeholder(title, skip[key], head=head))
            else:
                story.extend(self._render_unit(title, head, blocks))
        return story

    def _doc(self, target, **kwargs) -> SimpleDocTemplate:
        return SimpleDocTemplate(
            target,
            pagesize=A4,
            leftMargin=MARGIN_X,
            rightMargin=MARGIN_X,
            topMargin=MARGIN_TOP,
            bottomMargin=MARGIN_BOTTOM,
            **kwargs,
        )

    def _unrenderable_units(
        self, skip: dict[tuple[int, int], str]
    ) -> dict[tuple[int, int], tuple[str, str]]:
        """Lay out every unit alone and return those that fail."""
        bad: dict[tuple[int, int], tuple[str, str]] = {}
        for key, title, head, blocks in self._units():
            if key in skip:
                continue
            flowables = self._render_unit(title, head, blocks)
            try:
                self._doc(io.BytesIO()).build(flowables)
            except Exception as exc:
                kind = (
                    "layout error"
                    if isinstance(exc, LayoutError)
                    else type(exc).__name__
                )
                bad[key] = (title, f"{kind}: {(str(exc).splitlines() or [''])[0]}")
        return bad

    def build(self, path: str | os.PathLike[str]) -> Path:
        """Write the PDF to ``path`` and return it."""
        out = Path(path)
        device = self.doc.get("device") or ""
        generator = self.doc.get("generator") or "Sandroid"
        generated = self.doc.get("generated_at") or ""
        footer = f"{generator} · {device} · generated {generated}"
        seal = self.doc.get("seal") or {}
        meta = {
            "title": f"{self.doc.get('title') or DEFAULT_TITLE} – {device}",
            "author": "Sandroid (Fraunhofer FKIE)",
            "subject": (
                f"Timeline seal SHA-256 {seal['sha256']}"
                if seal.get("sha256")
                else "Sandroid report"
            ),
            "creator": str(generator),
        }
        skip: dict[tuple[int, int], str] = {}
        skipped: list[tuple[str, str]] = []
        while True:
            self._builder_errors = []
            self.story = self._story(skip)
            builder_errors = self._builder_errors
            try:
                self._doc(str(out), **meta).multiBuild(
                    list(self.story), canvasmaker=_make_canvas_class(footer)
                )
                break
            except Exception as exc:
                bad = self._unrenderable_units(skip)
                if not bad:
                    raise
                for key, (title, reason) in bad.items():
                    logger.error(
                        "PDF section %r does not fit on a page and is replaced "
                        "by a note (%s); the data is in report.json.",
                        title,
                        reason,
                    )
                    skip[key] = reason
                    skipped.append((title, reason))
                logger.debug("Retrying PDF layout after: %s", exc)
        self.degraded_sections = builder_errors + skipped
        return out

    # ---- blocks -----------------------------------------------------------

    def _block(self, block: Mapping[str, Any]) -> None:
        kind = block.get("type")
        handler = {
            "text": self._block_text,
            "heading": self._block_heading,
            "kv": self._block_kv,
            "table": self._block_table,
            "list": self._block_list,
            "image": lambda b: self._shots([b]),
            "transcript_step": self._block_step,
            "error": self._block_error,
        }.get(str(kind))
        if handler is None:
            self.elements.append(
                Paragraph(f"(unknown block type {_txt(kind)})", self.note_style)
            )
            return
        handler(block)

    def _style_for(self, level: Any) -> ParagraphStyle:
        if level == "error":
            return self.error_style
        if level == "warn":
            return self.warn_style
        return self.body_wrap

    def _block_text(self, block: Mapping[str, Any]) -> None:
        level = block.get("level")
        prefix = "<b>Warning:</b> " if level == "warn" else ""
        self.elements.append(
            Paragraph(prefix + _txt(block.get("text")), self._style_for(level))
        )
        self.elements.append(Spacer(10, 4))

    def _block_error(self, block: Mapping[str, Any]) -> None:
        self.elements.append(
            Paragraph(
                "<b>This part could not be built</b> "
                f"({_txt(_clip(str(block.get('error')), 300))}).",
                self.error_style,
            )
        )
        self.elements.append(Spacer(10, 6))

    def _block_heading(self, block: Mapping[str, Any]) -> None:
        level = int(block.get("level") or 2)
        style = self.headings.get(min(max(level, 2), 4))
        text = _txt(block.get("text"))
        if block.get("times"):
            text += f' <font size="7" color="#666666">{_txt(block["times"])}</font>'
        if level <= 2:
            self.elements.append(CondPageBreak(1.5 * inch))
        self.elements.append(Paragraph(text, style))
        if block.get("shots"):
            self._shots(block["shots"])

    def _block_kv(self, block: Mapping[str, Any]) -> None:
        mono = set(block.get("mono_keys") or [])
        rows = []
        for key, value in block.get("rows") or []:
            style = self.mono if key in mono else self.body_wrap
            rows.append(
                [
                    Paragraph(f"<b>{_txt(key)}</b>", self.body_wrap),
                    Paragraph(_txt(value), style),
                ]
            )
        if not rows:
            return
        if block.get("highlight_last"):
            table = Table(rows, colWidths=[FRAME_WIDTH - 80, 80])
            style = self._table_style(header=False)
            style.add("ALIGN", (1, 0), (1, -1), "RIGHT")
            style.add("BACKGROUND", (0, -1), (-1, -1), self.highlight_color)
        else:
            table = Table(rows, colWidths=[130, FRAME_WIDTH - 130])
            style = self._table_style(header=False)
        table.setStyle(style)
        self.elements.append(table)
        self.elements.append(Spacer(10, 10))

    def _widths(self, block: Mapping[str, Any], n: int) -> list[float]:
        hints = list(block.get("widths") or [])[:n]
        hints += [None] * (n - len(hints))
        fixed = sum(w for w in hints if isinstance(w, (int, float)))
        flexible = [i for i, w in enumerate(hints) if not isinstance(w, (int, float))]
        rest = max(FRAME_WIDTH - fixed, 40 * max(len(flexible), 1))
        return [
            float(w) if isinstance(w, (int, float)) else rest / len(flexible)
            for w in hints
        ]

    def _block_table(self, block: Mapping[str, Any]) -> None:
        columns = list(block.get("columns") or [])
        rows_in = block.get("rows") or []
        n = len(columns) or max((len(r) for r in rows_in), default=1)
        widths = self._widths(block, n)
        mono = set(block.get("mono_cols") or [])
        see_also = str(block.get("see_also") or "report.json")
        rows: list[list[Any]] = [self._header_row(columns)] if columns else []
        for row in rows_in:
            row = list(row) + [""] * (n - len(row))
            cells: list[list[Any]] = []
            for i, value in enumerate(row[:n]):
                style = self.mono if i in mono else self.body_wrap
                width = widths[i] - _CELL_HPAD
                if isinstance(value, list):
                    cells.append(
                        split_lines_into_cells(
                            [str(v) for v in value], style, width, see_also=see_also
                        )
                    )
                else:
                    cells.append(
                        [
                            bounded_lines_paragraph(
                                [_clip(str(value), MAX_ENTRY_CHARS)],
                                style,
                                width,
                                max_line_chars=MAX_ENTRY_CHARS + 40,
                                see_also=see_also,
                            )
                        ]
                    )
            parts = max(len(c) for c in cells)
            for part in range(parts):
                out = []
                for i, chunks in enumerate(cells):
                    if part < len(chunks):
                        out.append(chunks[part])
                    elif part > 0 and i == 0:
                        out.append(Paragraph(f"<i>{_txt(row[0])}</i>", self.body))
                    elif part > 0 and i == 1 and not isinstance(row[1], list):
                        out.append(
                            Paragraph(
                                f"<i>{_txt(_clip(str(row[1]), MAX_LINE_CHARS))} "
                                f"(continued, part {part + 1}/{parts})</i>",
                                self.body_wrap,
                            )
                        )
                    else:
                        out.append("")
                rows.append(out)
        if len(rows) <= (1 if columns else 0):
            self.elements.append(Paragraph("No entries.", self.note_style))
            return
        self.elements.append(self._table(rows, widths, header=bool(columns)))
        self.elements.append(Spacer(10, 12))

    def _block_list(self, block: Mapping[str, Any]) -> None:
        style = self._style_for(block.get("level"))
        for item in block.get("items") or []:
            self.elements.append(Paragraph(_txt(item), style, bulletText="•"))
        self.elements.append(Spacer(10, 6))

    def _shots(self, blocks: list[Mapping[str, Any]]) -> None:
        cell_w = FRAME_WIDTH / SHOTS_PER_ROW - 6
        cells: list[Any] = []
        for block in blocks:
            path, warning = self.images.resolve(block)
            caption = Paragraph(_txt(block.get("caption")), self.caption)
            if path is None:
                cells.append([Paragraph(_txt(warning), self.warn_style), caption])
                continue
            try:
                with PILImage.open(path) as im:
                    w, h = im.size
            except Exception as exc:
                cells.append(
                    [
                        Paragraph(
                            _txt(f"Unreadable screenshot: {exc}"), self.warn_style
                        ),
                        caption,
                    ]
                )
                continue
            scale = min(cell_w / w, SHOT_MAX_HEIGHT / h)
            cells.append([Image(str(path), width=w * scale, height=h * scale), caption])
        if not cells:
            return
        rows = []
        for i in range(0, len(cells), SHOTS_PER_ROW):
            chunk = cells[i : i + SHOTS_PER_ROW]
            chunk += [""] * (SHOTS_PER_ROW - len(chunk))
            rows.append(chunk)
        table = Table(rows, colWidths=[FRAME_WIDTH / SHOTS_PER_ROW] * SHOTS_PER_ROW)
        table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        self.elements.append(table)
        self.elements.append(Spacer(10, 4))

    def _thumbs(self, blocks: list[Mapping[str, Any]], right: list[Any]) -> Any:
        """Thumbnail grid for a step's screenshots (warnings go to ``right``)."""
        cells: list[Any] = []
        cell_w = THUMB_COL / THUMBS_PER_ROW
        for block in blocks:
            path, warning = self.images.resolve(block)
            if path is None:
                right.append(Paragraph(_txt(warning), self.warn_style))
                continue
            try:
                with PILImage.open(path) as im:
                    w, h = im.size
            except Exception as exc:
                right.append(
                    Paragraph(_txt(f"Unreadable screenshot: {exc}"), self.warn_style)
                )
                continue
            scale = min((cell_w - 6) / w, THUMB_MAX_HEIGHT / h)
            cells.append(
                [
                    Image(str(path), width=w * scale, height=h * scale),
                    Paragraph(_txt(block.get("caption")), self.caption),
                ]
            )
        if not cells:
            return None
        rows = [
            cells[i : i + THUMBS_PER_ROW]
            + [""] * (THUMBS_PER_ROW - len(cells[i : i + THUMBS_PER_ROW]))
            for i in range(0, len(cells), THUMBS_PER_ROW)
        ]
        grid = Table(rows, colWidths=[cell_w] * THUMBS_PER_ROW)
        grid.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 1),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 1),
                ]
            )
        )
        return grid

    def _block_step(self, step: Mapping[str, Any]) -> None:
        kind = str(step.get("kind") or "").replace("_", " ")
        actor = step.get("actor")
        if step.get("src") == "input" and actor not in (None, "user"):
            kind += f" · {actor}"
        left = Paragraph(
            f"<b>{_txt(_clock(step.get('t'), ms=True))}</b><br/>"
            f"{_txt(kind)}<br/>"
            f'<font size="6" color="#777777">#{_txt(step.get("seq"))}</font>',
            self.body,
        )
        title = _txt(step_title(step))
        if step.get("confirmed"):
            title += ' <font color="#0C9A7C">✓ confirmed</font>'
        style = self.warn_style if step.get("level") == "warn" else self.body_wrap
        right: list[Any] = [Paragraph(f"<b>{title}</b>", style)]
        if step.get("kind") == "text":
            if step.get("text_masked"):
                right.append(Paragraph("Typed text: <i>masked</i>", self.body_wrap))
            elif step.get("text") is not None:
                note = " (password field)" if step.get("password") else ""
                right.append(
                    Paragraph(
                        "Typed text: <font name='Courier'>"
                        f"{_txt(_clip(str(step['text']), 500))}</font>{note}",
                        self.body_wrap,
                    )
                )
        if step.get("src") != "screen":
            screen = _screen_text(step.get("screen"))
            if screen:
                right.append(Paragraph(f"Screen: {_txt(screen)}", self.small))
        for line in effect_lines(step):
            right.append(Paragraph(_txt(_clip(line, 1500)), self.small))
        if step.get("shot_note"):
            right.append(Paragraph(f"<i>{_txt(step['shot_note'])}</i>", self.small))
        thumbs = self._thumbs(step.get("shots") or [], right)
        if thumbs is not None:
            row = [left, right, thumbs]
            widths = [62, FRAME_WIDTH - 62 - THUMB_COL, THUMB_COL]
        else:
            row, widths = [left, right], [62, FRAME_WIDTH - 62]
        table = Table([row], colWidths=widths)
        table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.3, self.table_line_color),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        self.elements.append(table)


def render_pdf(
    doc: Mapping[str, Any],
    out: str | os.PathLike[str],
    *,
    base_dir: str | os.PathLike[str] | None = None,
) -> Path:
    """Render ``doc`` (a ``report.json`` document) to the PDF ``out``.

    Sections that cannot be laid out are replaced by a note and logged.
    """
    path = Path(out)
    renderer = PdfRenderer(doc, Path(base_dir) if base_dir else path.parent)
    renderer.build(path)
    for title, reason in renderer.degraded_sections:
        logger.warning("PDF report section %r omitted: %s", title, reason)
    logger.info("PDF report generated: %s (SHA-256 %s)", path, sha256_file(path))
    return path


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

_MD_SPECIAL = str.maketrans(
    {c: f"\\{c}" for c in "\\`*_[]<>|"} | {"\n": " ", "\r": " "}
)


def _md(value: Any) -> str:
    """Inline Markdown text with Markdown/HTML syntax characters escaped."""
    if value is None:
        return "–"
    return plain_text(str(value)).translate(_MD_SPECIAL)


def _code(value: Any) -> str:
    """Inline code span that survives backticks in ``value``."""
    text = plain_text(str(value)).replace("\n", " ")
    fence = "`"
    while fence in text:
        fence += "`"
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _md_cell(value: Any, see_also: str) -> str:
    if isinstance(value, list):
        lines = [_clip(str(v), MAX_LINE_CHARS) for v in value]
        shown = lines[:MAX_DIFF_LINES_TOTAL]
        text = "<br>".join(_md(v) for v in shown)
        if len(lines) > len(shown):
            text += (
                f"<br>*… {len(lines) - len(shown)} more line(s) not shown — "
                f"see {_md(see_also)}*"
            )
        return text or " "
    return _md(_clip(str(value), MAX_ENTRY_CHARS)) if value != "" else " "


class MarkdownRenderer:
    """Render a report document as GitHub-flavoured Markdown."""

    def __init__(self, doc: Mapping[str, Any], base_dir: Path):
        self.doc = doc
        self.base_dir = Path(base_dir)
        self.images = ImageCheck(self.base_dir)
        self.out: list[str] = []

    def render(self) -> str:
        doc = self.doc
        self.out = [f"# {_md(doc.get('title') or DEFAULT_TITLE)}", ""]
        meta = [
            f"Generated {_md(doc.get('generated_at'))} by {_md(doc.get('generator'))}",
            f"schema {_code(doc.get('schema'))}",
        ]
        if doc.get("device"):
            meta.insert(0, f"Device {_md(doc['device'])}")
        self.out += [" · ".join(meta), ""]
        regenerated = doc.get("regenerated")
        if isinstance(regenerated, Mapping):
            self.out += [
                f"> **Regenerated** from {_md(regenerated.get('from'))}: "
                f"{_md(regenerated.get('reason'))}",
                "",
            ]
        for section in doc.get("sections") or []:
            if not isinstance(section, Mapping):
                continue
            self.out += [f"## {_md(section.get('title') or section.get('id'))}", ""]
            for block in section.get("blocks") or []:
                try:
                    self._block(block)
                except Exception as exc:  # never lose the whole file
                    logger.error("Markdown block failed: %s", exc, exc_info=True)
                    self.out += [f"> **Error:** block not rendered ({_md(exc)})", ""]
        return "\n".join(self.out).rstrip() + "\n"

    def _block(self, block: Mapping[str, Any]) -> None:
        kind = block.get("type")
        if kind != "transcript_step" and self.out and self.out[-1] != "":
            self.out.append("")  # end a run of transcript steps
        if kind == "text":
            level = block.get("level")
            text = _md(block.get("text"))
            if level == "warn":
                text = f"> **Warning:** {text}"
            elif level == "error":
                text = f"> **{text}**"
            self.out += [text, ""]
        elif kind == "error":
            self.out += [
                f"> **Error:** this part could not be built ({_md(block.get('error'))})",
                "",
            ]
        elif kind == "heading":
            level = min(int(block.get("level") or 2) + 1, 6)
            text = _md(block.get("text"))
            if block.get("times"):
                text += f" · {_md(block['times'])}"
            self.out += [f"{'#' * level} {text}", ""]
            if block.get("shots"):
                self.out += [*self._shot_lines(block["shots"], indent=""), ""]
        elif kind == "kv":
            self.out += ["| | |", "|---|---|"]
            for key, value in block.get("rows") or []:
                self.out.append(f"| **{_md(key)}** | {_md(value)} |")
            self.out.append("")
        elif kind == "table":
            self._table(block)
        elif kind == "list":
            prefix = "**" if block.get("level") == "error" else ""
            for item in block.get("items") or []:
                self.out.append(f"- {prefix}{_md(item)}{prefix}")
            self.out.append("")
        elif kind == "image":
            self.out += [*self._shot_lines([block], indent=""), ""]
        elif kind == "transcript_step":
            self._step(block)
        else:
            self.out += [f"*(unknown block type {_md(kind)})*", ""]

    def _table(self, block: Mapping[str, Any]) -> None:
        columns = list(block.get("columns") or [])
        rows = block.get("rows") or []
        n = len(columns) or max((len(r) for r in rows), default=1)
        if not rows:
            self.out += ["*No entries.*", ""]
            return
        see_also = str(block.get("see_also") or "report.json")
        header = columns or [" "] * n
        self.out.append("| " + " | ".join(_md(c) for c in header) + " |")
        self.out.append("|" + "---|" * n)
        for row in rows:
            row = list(row) + [""] * (n - len(row))
            self.out.append(
                "| " + " | ".join(_md_cell(v, see_also) for v in row[:n]) + " |"
            )
        self.out.append("")

    def _shot_lines(self, blocks: list[Mapping[str, Any]], indent: str) -> list[str]:
        out = []
        for block in blocks:
            path, warning = self.images.resolve(block)
            caption = _md(block.get("caption") or "screenshot")
            if path is None:
                out.append(f"{indent}- > **Warning:** {_md(warning)}")
                continue
            link = Path(os.path.relpath(path, self.base_dir)).as_posix()
            link = link.replace(" ", "%20").replace("(", "%28").replace(")", "%29")
            out.append(f"{indent}- ![{caption}]({link})")
        return out

    def _step(self, step: Mapping[str, Any]) -> None:
        when = _clock(step.get("t"), ms=True)
        kind = str(step.get("kind") or "").replace("_", " ")
        title = _md(step_title(step))
        line = f"- **{when}** · {kind} · {title} · #{step.get('seq')}"
        if step.get("confirmed"):
            line += " ✓"
        if step.get("level") == "warn":
            line += " ⚠"
        self.out.append(line)
        if step.get("kind") == "text":
            if step.get("text_masked"):
                self.out.append("  - Typed text: *masked*")
            elif step.get("text") is not None:
                note = " (password field)" if step.get("password") else ""
                self.out.append(
                    f"  - Typed text: {_code(_clip(str(step['text']), 500))}{note}"
                )
        if step.get("src") != "screen":
            screen = _screen_text(step.get("screen"))
            if screen:
                self.out.append(f"  - Screen: {_md(screen)}")
        for effect in effect_lines(step):
            self.out.append(f"  - {_md(_clip(effect, 1500))}")
        if step.get("shot_note"):
            self.out.append(f"  - *{_md(step['shot_note'])}*")
        if step.get("shots"):
            self.out += self._shot_lines(step["shots"], indent="  ")


def render_markdown(
    doc: Mapping[str, Any], *, base_dir: str | os.PathLike[str] | None = None
) -> str:
    """Markdown for ``doc``; image links are relative to ``base_dir``."""
    return MarkdownRenderer(doc, Path(base_dir) if base_dir else Path.cwd()).render()


__all__ = [
    "FooterCanvas",
    "ImageCheck",
    "MarkdownRenderer",
    "PdfRenderer",
    "bounded_lines_paragraph",
    "effect_lines",
    "render_markdown",
    "render_pdf",
    "split_lines_into_cells",
    "step_title",
]
