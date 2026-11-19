"""Theme definitions and CSS files for Sandroid TUI.

This module provides 13 color themes for the TUI interface:
- 4 standard themes: default, dark, light, high_contrast
- 2 tuned light themes: paper (warm, print-like), daylight (crisp, projector)
- 4 new themes: cyberpunk, nord, dracula, solarized
- 3 dark themes tuned for reading dense tables: graphite, deep_sea, evergreen

Themes are picked in Settings (``,``) → Appearance. ``Ctrl+T`` is not a
theme key: it toggles Tracking (session timeline).

Each theme has a corresponding CSS file in this directory.
"""

from dataclasses import dataclass, field, fields, replace
from pathlib import Path

from textual._context import active_app
from textual.theme import BUILTIN_THEMES
from textual.theme import Theme as TextualTheme

# Directory containing theme CSS files
THEMES_DIR = Path(__file__).parent

# Parent directory for default theme CSS
PARENT_DIR = THEMES_DIR.parent


# ========== App lens color tokens ==========
#
# One token set per Sandroid theme colors the App lens (``LensSection``
# tables, the ``SpotlightPanel`` status/bypass rows and action row, the
# ``Inspector``). Each token is used in two ways, both fed from here:
#
# * CSS: every token is a Textual CSS variable ``$lens-<name>`` (underscores
#   become dashes, e.g. ``cursor_focus`` -> ``$lens-cursor-focus``) on the
#   Textual theme ``sandroid-<theme name>`` that ``SandroidTUI`` registers
#   per Sandroid theme (see :func:`build_textual_theme`).
# * Python/Rich: :func:`lens_palette` returns the palette of the running
#   app's current theme (``lens_palette().warn`` etc.).
#
# Tokens (role -> where it shows today):
#   bg                 lens background: section tables, spotlight scroll area
#   panel              panel background: spotlight header line behind the scroll
#   text               primary text: section cells without their own color
#   label              row-label text: the right-aligned key column of key/value
#                      rows (identity...) and of the spotlight status rows
#   dim                dim text: placeholders, "none", secondary cell values
#   muted              muted text: Inspector subtitle, tab strip, headings
#   title              section titles on the header bands
#   accent             accent: spotlight header line, active Inspector tab
#   accent_text        text drawn on ``accent`` (active Inspector tab)
#   ok / warn / bad    status colors (granted / dangerous / denied ...)
#   rule               spare (the section separator line before header bands)
#   rule_focus         spare (the focused section's line before header bands)
#   header             table column header text
#   cursor             row cursor background, section not focused
#   cursor_focus       row cursor background, section focused
#   action_bg/_text    spotlight action row ("Start  R restart ...")
#   action_hover_bg/_text   an action cell under the mouse
#   input_bg/_focus_bg/_text  the row filter input ("/")
#   band               section header band (top border of each section)
#   band_focus         header band of the focused section
#   stripe             zebra stripe of the longer tables (permissions, ...)
#   cursor_keeps_colors  (bool, not a CSS variable) True: a cell keeps its
#                      own color under the row cursor (``dangerous`` stays
#                      amber) instead of taking the cursor text color.
#
# Add a theme: give its ``Theme(...)`` a ``lens=LensPalette(...)``; it is
# registered automatically (``THEMES``). Retune: change the value here.
# A light theme also needs ``status_colors`` (dark shades of FIXED_COLORS),
# ``textual_variables`` (footer/scrollbar/cursor of Textual's widgets), a
# ``<name>.tcss`` whose last section re-colors the shell chrome (see
# paper.tcss), and its id in config/schema.py + config/cli/helpers.py.
# New token: add a field to ``LensPalette`` AND a value in every palette
# below, then use ``$lens-<name>`` in a DEFAULT_CSS or ``lens_palette().<name>``
# in Python. An App hosting lens widgets must provide the variables:
# ``SandroidTUI`` does (``get_theme_variable_defaults`` + registered themes);
# ``tests/conftest.py`` adds the defaults to bare test ``App``s.


@dataclass(frozen=True)
class LensPalette:
    """App lens color tokens (see the table above). Hex strings."""

    bg: str
    panel: str
    text: str
    label: str
    dim: str
    muted: str
    title: str
    accent: str
    accent_text: str
    ok: str
    warn: str
    bad: str
    rule: str
    rule_focus: str
    header: str
    cursor: str
    cursor_focus: str
    action_bg: str
    action_text: str
    action_hover_bg: str
    action_hover_text: str
    input_bg: str
    input_focus_bg: str
    input_text: str
    band: str
    band_focus: str
    stripe: str
    cursor_keeps_colors: bool = False

    def css_variables(self) -> dict[str, str]:
        """The tokens as Textual CSS variables (``{"lens-bg": "#050811", ...}``)."""
        return {
            "lens-" + f.name.replace("_", "-"): getattr(self, f.name)
            for f in fields(self)
            if isinstance(getattr(self, f.name), str)
        }


# Midnight Cyan: the exact colors the lens hardcoded before tokens existed
# (``text`` is textual-dark's ``$foreground``, which the tables inherited).
# Since the header bands: ``label`` is lighter (a readable key column) and
# ``band`` / ``band_focus`` / ``stripe`` are new.
DEFAULT_LENS = LensPalette(
    bg="#050811",
    panel="#080c18",
    text="#e0e0e0",
    label="#8796b8",
    dim="#5b6479",
    muted="#8f9bb3",
    title="#7dd3fc",
    accent="#38bdf8",
    accent_text="#06121f",
    ok="#4ade80",
    warn="#fbbf24",
    bad="#fb7185",
    rule="#1f2d4d",
    rule_focus="#38bdf8",
    header="#5b6479",
    cursor="#0b1628",
    cursor_focus="#1d3557",
    action_bg="#0b1628",
    action_text="#93a4c3",
    action_hover_bg="#1f2937",
    action_hover_text="#7dd3fc",
    input_bg="#0b1628",
    input_focus_bg="#11203a",
    input_text="#e5e9f0",
    band="#0f1c33",
    band_focus="#173560",
    stripe="#0a1121",
)


@dataclass
class Theme:
    """TUI theme definition.

    Contains all color values used throughout the TUI interface.
    Colors are specified as hex strings (e.g., "#FF00FF").
    """

    name: str  # Internal identifier
    display_name: str  # Human-readable name
    is_dark: bool  # Whether this is a dark theme

    # Primary colors
    primary: str  # Main accent color (headers, titles)
    secondary: str  # Secondary accent color
    accent: str  # Highlight/active color

    # Background colors
    background: str  # Main background
    surface: str  # Elevated surface (panels, modals)

    # Status colors
    error: str  # Error messages
    warning: str  # Warning messages
    success: str  # Success messages

    # Text colors
    text: str  # Primary text
    text_muted: str  # Secondary/dimmed text

    # UI element colors
    key_color: str = "#ff00ff"  # Menu key brackets color (magenta by default)
    border_color: str = "#333333"  # Border/divider color

    # Additional colors for views
    forensic_color: str = "#4CAF50"  # Green for forensic view
    malware_color: str = "#FF5252"  # Red for malware view
    security_color: str = "#FFC107"  # Yellow for security view

    # Logo colors
    logo_color: str = "#00ff00"  # Main logo color (bright green by default)
    logo_text_color: str = "#ffffff"  # "Sandroid" text in logo (white by default)

    # AI Chat panel colors (see tui/widgets/chat_panel.py) -- these back
    # inline Rich-markup colors built in Python (NOT CSS chrome, which is
    # themed separately via the .tcss files' ChatPanel/#chat-* selectors).
    # No existing field above was a good semantic fit for any of these, so
    # they're their own fields; every theme below sets its own value.
    tool_color: str = "#a78bfa"  # Tool-call bullet/label (purple by default)
    user_highlight_background: str = "#1c2333"  # User-line highlight band bg
    assistant_reply_color: str = "#4ade80"  # Assistant reply text (soft green)
    waiting_color: str = "#fbbf24"  # "waiting on you" amber (distinct from warning)
    muted_status_color: str = "#5b6479"  # Idle/muted chat status text

    # Muted text in the shell header's breadcrumb ("no device", "A14 · root");
    # None = text_muted. Set when the theme's header band is not the
    # background text_muted was picked for (daylight: dark bar, light page).
    header_muted: str | None = None

    # App lens color tokens (see LensPalette above).
    lens: LensPalette = field(default_factory=lambda: DEFAULT_LENS)

    # Replacements for FIXED_COLORS entries (see :func:`fixed_color`). Empty
    # for the dark themes; a light theme swaps the bright "running" green and
    # friends, which are unreadable on a white background.
    status_colors: dict[str, str] = field(default_factory=dict)

    # Extra Textual CSS variables for this theme's registered Textual theme
    # (see :func:`build_textual_theme`): footer, scrollbar and cursor colors of
    # Textual's own widgets, which the .tcss file cannot reach.
    textual_variables: dict[str, str] = field(default_factory=dict)


# ========== Fixed Semantic Colors ==========
# These colors do NOT change between the dark themes - they provide consistent
# status recognition, like traffic lights (green=go, red=stop). A light theme
# keeps the same hues but darker shades (``Theme.status_colors``): read them
# with :func:`fixed_color`, never ``FIXED_COLORS[...]`` directly.

FIXED_COLORS = {
    # Status indicators - universally recognizable
    "running": "#00ff00",  # Bright shiny green - active/running state
    "stopped": "#ff5555",  # Bright red - stopped/inactive state
    "error": "#ff5555",  # Bright red - error state (same as stopped)
    "warning_status": "#ffaa00",  # Bright amber - warning/caution state
    # Mode indicators - matching Rich console mode colors
    # SPAWN = cyan (cold/fresh - launching new process)
    # ATTACH = green (connected/live - attached to running process)
    "spawn_mode": "#00ffff",  # Bright cyan - spawn mode
    "attach_mode": "#00ff00",  # Bright green - attach mode (same as running)
    # Transitional states and notes
    "paused": "#fbbf24",  # Amber - paused / restarting app
    "notice": "#facc15",  # Yellow - version mismatch, label marks in the log
}


# ========== Theme Definitions ==========

# Default theme: Midnight Cyan
DEFAULT_THEME = Theme(
    name="default",
    display_name="Midnight Cyan",
    is_dark=True,
    primary="#38bdf8",  # section_title - bright cyan
    secondary="#7dd3fc",  # header_text - softer cyan
    accent="#00ff00",  # bright/shiny green for running states
    background="#050811",  # almost-black, slightly blue
    surface="#080c18",  # panel_background - slightly lighter
    error="#fb7185",  # log_error - soft red
    warning="#facc15",  # log_warn - soft yellow
    success="#00ff00",  # bright/shiny green for success/running
    text="#e5e9f0",  # text_primary - light grey
    text_muted="#8f9bb3",  # text_secondary - muted grey-blue
    key_color="#ff00ff",  # magenta keys (classic terminal look)
    border_color="#111827",  # subtle border
    forensic_color="#2dd4bf",  # teal/mint green (distinct from running green)
    malware_color="#fb7185",  # soft red
    security_color="#facc15",  # soft yellow
    logo_color="#00ff00",  # bright green logo
    logo_text_color="#ffffff",  # white "Sandroid" text
    tool_color="#a78bfa",  # purple -- exact reproduction of the prior
    # hardcoded chat_panel.py literal, preserving today's look exactly
    user_highlight_background="#1c2333",  # dark navy -- exact reproduction
    assistant_reply_color="#4ade80",  # soft green -- exact reproduction
    waiting_color="#fbbf24",  # amber -- exact reproduction
    muted_status_color="#5b6479",  # muted gray -- exact reproduction
    lens=DEFAULT_LENS,
)

DARK_THEME = Theme(
    name="dark",
    display_name="Dark",
    is_dark=True,
    primary="#BB86FC",  # Purple - Material Design
    secondary="#3700B3",  # Deep purple
    accent="#03DAC6",  # Teal accent
    background="#000000",  # Pure black
    surface="#121212",  # Dark surface
    error="#CF6679",  # Pink error
    warning="#FFB74D",  # Orange warning
    success="#81C784",  # Green success
    text="#E0E0E0",  # Light grey text
    text_muted="#757575",  # Medium grey
    key_color="#03DAC6",  # Teal keys (Material teal)
    border_color="#333333",  # Dark border
    forensic_color="#81C784",  # Green
    malware_color="#CF6679",  # Pink
    security_color="#FFB74D",  # Orange
    logo_color="#03DAC6",  # Teal logo
    logo_text_color="#BB86FC",  # Purple "Sandroid" text
    tool_color="#BB86FC",  # matches this theme's .tool-tab.-active/#chat-header
    # color chosen in themes/dark.tcss (== primary) -- keeps the chat
    # transcript's tool-call color visually consistent with the chrome
    user_highlight_background="#333333",  # this theme's .tool-tab:hover bg --
    # already an established "lighter highlight" shade for this theme
    assistant_reply_color="#81C784",  # == success -- a soft Material green,
    # already an appropriate readable reply color for this theme
    waiting_color="#FFC107",  # Material Amber 500 -- distinct from this
    # theme's warning (#FFB74D, more orange)
    muted_status_color="#757575",  # == text_muted, == this theme's
    # .tool-tab inactive color -- consistent with the chrome
    lens=LensPalette(
        bg="#0A0A0A",
        panel="#121212",
        text="#E0E0E0",
        label="#9E9E9E",
        dim="#8A8A8A",
        muted="#9E9E9E",
        title="#BB86FC",
        accent="#03DAC6",
        accent_text="#000000",
        ok="#81C784",
        warn="#FFB74D",
        bad="#CF6679",
        rule="#333333",
        rule_focus="#BB86FC",
        header="#8A8A8A",
        cursor="#1E1E1E",
        cursor_focus="#383838",
        action_bg="#1E1E1E",
        action_text="#BDBDBD",
        action_hover_bg="#333333",
        action_hover_text="#BB86FC",
        input_bg="#1E1E1E",
        input_focus_bg="#2A2A2A",
        input_text="#E0E0E0",
        band="#1A1A1A",
        band_focus="#2E2540",
        stripe="#111111",
    ),
)

LIGHT_THEME = Theme(
    name="light",
    display_name="Light",
    is_dark=False,
    primary="#1976D2",  # Blue
    secondary="#0D47A1",  # Dark blue
    accent="#00BFA5",  # Teal accent
    background="#FAFAFA",  # Off-white
    surface="#FFFFFF",  # White
    error="#D32F2F",  # Red
    warning="#F57C00",  # Orange
    success="#388E3C",  # Green
    text="#212121",  # Dark grey
    text_muted="#757575",  # Medium grey
    key_color="#0D47A1",  # Dark blue keys
    border_color="#E0E0E0",  # Light border
    forensic_color="#388E3C",  # Green
    malware_color="#D32F2F",  # Red
    security_color="#F57C00",  # Orange
    logo_color="#1976D2",  # Blue logo
    logo_text_color="#0D47A1",  # Dark blue "Sandroid" text
    tool_color="#1976D2",  # == primary, == this theme's .tool-tab.-active
    # color in themes/light.tcss -- consistent with the chrome
    user_highlight_background="#E3F2FD",  # this theme's .tool-tab:hover bg --
    # a light blue tint that actually stands out against the near-white
    # #chat-log background (surface/background are both too close to white)
    assistant_reply_color="#388E3C",  # == success -- dark enough green for
    # readable contrast against this theme's light background
    waiting_color="#FFA000",  # Material Amber 700 -- distinct from this
    # theme's warning (#F57C00, more orange), still readable on white
    muted_status_color="#757575",  # == text_muted, == this theme's
    # .tool-tab inactive color -- consistent with the chrome
    lens=LensPalette(
        bg="#FFFFFF",
        panel="#FAFAFA",
        text="#212121",
        label="#5F6368",
        dim="#6B6B6B",
        muted="#5F6368",
        title="#0D47A1",
        accent="#1976D2",
        accent_text="#FFFFFF",
        ok="#2E7D32",
        warn="#B45309",
        bad="#C62828",
        rule="#D0D7DE",
        rule_focus="#1976D2",
        header="#6B6B6B",
        cursor="#EEF3F8",
        cursor_focus="#BBDEFB",
        action_bg="#E3F2FD",
        action_text="#37474F",
        action_hover_bg="#BBDEFB",
        action_hover_text="#0D47A1",
        input_bg="#F5F5F5",
        input_focus_bg="#E3F2FD",
        input_text="#212121",
        band="#EDF2F8",
        band_focus="#D3E5FA",
        stripe="#F6F8FB",
    ),
    status_colors={
        "running": "#2E7D32",
        "stopped": "#C62828",
        "error": "#C62828",
        "warning_status": "#B45309",
        "spawn_mode": "#00838F",
        "attach_mode": "#2E7D32",
        "paused": "#B45309",
        "notice": "#B45309",
    },
)

# Paper: warm off-white, ink-like near-black text, one restrained petrol-blue
# accent; quiet like a printed report. Contrast (WCAG) on the lens bg #FBF8F1:
# text 16.0, label 6.0, dim/header 5.5, title 9.0, ok 6.2, warn 5.7, bad 6.6
# (all >= 5.0 on the panel and the focused-section tint). Labels are a
# petrol grey, not a lighter ink, so the key column reads as labels.
PAPER_INK = "#1F1C17"
PAPER_PETROL = "#1C5D7C"
PAPER_OK = "#2D6A2F"
PAPER_WARN = "#8F5600"
PAPER_BAD = "#A3302A"

PAPER_THEME = Theme(
    name="paper",
    display_name="Paper",
    is_dark=False,
    primary=PAPER_PETROL,  # petrol blue
    secondary="#174A63",  # deep petrol
    accent="#2A6F6B",  # deep teal
    background="#F3EEE2",  # chrome: kraft paper
    surface="#FBF8F1",  # lens: off-white sheet
    error=PAPER_BAD,  # brick red
    warning=PAPER_WARN,  # ochre (never yellow on paper)
    success=PAPER_OK,  # forest green
    text=PAPER_INK,  # warm ink
    text_muted="#6B6459",  # pencil grey
    key_color="#174A63",
    border_color="#DCD3C0",
    forensic_color=PAPER_OK,
    malware_color=PAPER_BAD,
    security_color=PAPER_WARN,
    logo_color=PAPER_PETROL,
    logo_text_color=PAPER_INK,
    tool_color="#6A4A86",  # muted plum
    user_highlight_background="#ECE5D6",
    assistant_reply_color=PAPER_OK,
    waiting_color="#9C4A00",  # burnt orange, distinct from the ochre warning
    muted_status_color="#6B6459",
    header_muted="#5F584D",  # on the kraft header bar (5.4:1)
    lens=LensPalette(
        bg="#FBF8F1",
        panel="#F3EEE2",
        text=PAPER_INK,
        label="#3F6475",
        dim="#6B6459",
        muted="#5F584D",
        title="#174A63",
        accent=PAPER_PETROL,
        accent_text="#FFFFFF",
        ok=PAPER_OK,
        warn=PAPER_WARN,
        bad=PAPER_BAD,
        rule="#D6CCB6",
        rule_focus=PAPER_PETROL,
        header="#6B6459",
        cursor="#F2ECE0",
        cursor_focus="#D3E2E9",
        action_bg="#ECE5D6",
        action_text="#3D382F",
        action_hover_bg="#D3E2E9",
        action_hover_text="#174A63",
        input_bg="#F3EEE2",
        input_focus_bg="#E4EDF1",
        input_text=PAPER_INK,
        band="#EEE7D7",
        band_focus="#DDE8EB",
        stripe="#F7F3EA",
    ),
    status_colors={
        "running": PAPER_OK,
        "stopped": PAPER_BAD,
        "error": PAPER_BAD,
        "warning_status": PAPER_WARN,
        "spawn_mode": PAPER_PETROL,
        "attach_mode": PAPER_OK,
        "paused": PAPER_WARN,
        "notice": PAPER_WARN,
    },
    textual_variables={
        "footer-background": "#ECE5D6",
        "footer-foreground": PAPER_INK,
        "footer-description-foreground": "#3D382F",
        "footer-key-foreground": PAPER_PETROL,
        "scrollbar": "#C9BFAA",
        "scrollbar-hover": "#A89C84",
        "scrollbar-active": PAPER_PETROL,
        "scrollbar-background": "#F3EEE2",
        "scrollbar-background-hover": "#F3EEE2",
        "scrollbar-background-active": "#F3EEE2",
        "scrollbar-corner-color": "#F3EEE2",
        "block-cursor-foreground": PAPER_INK,
        "block-cursor-blurred-foreground": PAPER_INK,
    },
)

# Daylight: crisp cool white, near-black text, one vivid indigo accent; built
# for a bright office or a projector. Contrast (WCAG) on the lens bg #FFFFFF:
# text 18.7, label 7.9, dim/header 5.9, title 10.9, ok 5.4, warn 5.6, bad 6.0
# (all >= 4.9 on the panel and the focused-section tint). Header and footer
# are deep indigo bars (daylight.tcss) that hold their weight on a projector.
DAYLIGHT_INK = "#0A1222"
DAYLIGHT_INDIGO = "#4338E0"
DAYLIGHT_OK = "#0B7A3B"
DAYLIGHT_WARN = "#A05300"
DAYLIGHT_BAD = "#C21A30"

DAYLIGHT_THEME = Theme(
    name="daylight",
    display_name="Daylight",
    is_dark=False,
    primary=DAYLIGHT_INDIGO,  # vivid indigo
    secondary="#2B2A9E",  # deep indigo
    accent="#0F766E",  # teal
    background="#F2F5FA",  # chrome: cool light grey
    surface="#FFFFFF",  # lens: white
    error=DAYLIGHT_BAD,  # crimson
    warning=DAYLIGHT_WARN,  # burnt amber (never yellow on white)
    success=DAYLIGHT_OK,  # green
    text=DAYLIGHT_INK,  # blue-black
    text_muted="#5B6576",  # slate
    key_color="#2B2A9E",
    border_color="#D3DAE6",
    forensic_color=DAYLIGHT_OK,
    malware_color=DAYLIGHT_BAD,
    security_color=DAYLIGHT_WARN,
    logo_color=DAYLIGHT_INDIGO,
    logo_text_color=DAYLIGHT_INK,
    tool_color="#8A2BB8",  # violet
    user_highlight_background="#E8ECFF",
    assistant_reply_color=DAYLIGHT_OK,
    waiting_color="#B84A00",  # orange, distinct from the amber warning
    muted_status_color="#5B6576",
    header_muted="#B9C2FF",  # on the deep indigo header bar (9.4:1)
    lens=LensPalette(
        bg="#FFFFFF",
        panel="#F2F5FA",
        text=DAYLIGHT_INK,
        label="#3D4F86",
        dim="#5B6576",
        muted="#46557F",
        title="#2B2A9E",
        accent=DAYLIGHT_INDIGO,
        accent_text="#FFFFFF",
        ok=DAYLIGHT_OK,
        warn=DAYLIGHT_WARN,
        bad=DAYLIGHT_BAD,
        rule="#D3DAE6",
        rule_focus=DAYLIGHT_INDIGO,
        header="#5B6576",
        cursor="#F1F4F9",
        cursor_focus="#D3D8FF",
        action_bg="#E8EDF7",
        action_text="#1F2A44",
        action_hover_bg="#D3D8FF",
        action_hover_text="#2B2A9E",
        input_bg="#F2F5FA",
        input_focus_bg="#ECEEFF",
        input_text=DAYLIGHT_INK,
        band="#EDF0F8",
        band_focus="#E0E4FF",
        stripe="#F7F9FC",
    ),
    status_colors={
        "running": DAYLIGHT_OK,
        "stopped": DAYLIGHT_BAD,
        "error": DAYLIGHT_BAD,
        "warning_status": DAYLIGHT_WARN,
        "spawn_mode": "#0F766E",
        "attach_mode": DAYLIGHT_OK,
        "paused": DAYLIGHT_WARN,
        "notice": DAYLIGHT_WARN,
    },
    textual_variables={
        # The footer is the dark indigo bar of daylight.tcss (header too).
        "footer-background": "#1A1D45",
        "footer-foreground": "#E4E7FF",
        "footer-description-foreground": "#E4E7FF",
        "footer-key-foreground": "#B9C2FF",
        "scrollbar": "#B8C2D6",
        "scrollbar-hover": "#8E9AB3",
        "scrollbar-active": DAYLIGHT_INDIGO,
        "scrollbar-background": "#F2F5FA",
        "scrollbar-background-hover": "#F2F5FA",
        "scrollbar-background-active": "#F2F5FA",
        "scrollbar-corner-color": "#F2F5FA",
        "block-cursor-foreground": DAYLIGHT_INK,
        "block-cursor-blurred-foreground": DAYLIGHT_INK,
    },
)

HIGH_CONTRAST_THEME = Theme(
    name="high_contrast",
    display_name="High Contrast",
    is_dark=True,
    primary="#FFFF00",  # Yellow headers
    secondary="#00FFFF",  # Cyan
    accent="#FF00FF",  # Magenta
    background="#000000",  # Pure black
    surface="#000000",  # Pure black
    error="#FF0000",  # Pure red
    warning="#FFFF00",  # Yellow
    success="#00FF00",  # Pure green
    text="#FFFFFF",  # Pure white
    text_muted="#CCCCCC",  # Light grey
    key_color="#00FFFF",  # Cyan keys (high visibility)
    border_color="#FFFFFF",  # White border
    forensic_color="#00FF00",  # Green
    malware_color="#FF0000",  # Red
    security_color="#FFFF00",  # Yellow
    logo_color="#00FF00",  # Bright green logo
    logo_text_color="#FFFF00",  # Yellow "Sandroid" text
    tool_color="#FFFF00",  # == primary, == this theme's .tool-tab.-active
    # color in themes/high_contrast.tcss -- consistent with the chrome
    user_highlight_background="#333333",  # this theme's .tool-tab:hover bg --
    # clearly visible against pure black (surface is also pure black, i.e.
    # zero contrast, unacceptable for an accessibility-focused theme)
    assistant_reply_color="#00FF00",  # == success -- pure green, matching
    # this theme's maximum-contrast design intent
    waiting_color="#FFA500",  # pure orange -- clearly distinct from this
    # theme's pure-yellow warning, still maximally visible on black
    muted_status_color="#CCCCCC",  # == text_muted, == this theme's
    # .tool-tab inactive color -- consistent with the chrome
    lens=LensPalette(
        bg="#000000",
        panel="#000000",
        text="#FFFFFF",
        label="#E0E0E0",
        dim="#CCCCCC",
        muted="#E0E0E0",
        title="#FFFF00",
        accent="#00FFFF",
        accent_text="#000000",
        ok="#00FF00",
        warn="#FFFF00",
        bad="#FF5555",
        rule="#FFFFFF",
        rule_focus="#FFFF00",
        header="#00FFFF",
        cursor="#333333",
        cursor_focus="#0000CC",
        action_bg="#1A1A1A",
        action_text="#FFFFFF",
        action_hover_bg="#FFFF00",
        action_hover_text="#000000",
        input_bg="#1A1A1A",
        input_focus_bg="#333333",
        input_text="#FFFFFF",
        band="#1A1A1A",
        band_focus="#00006E",
        stripe="#0E0E0E",
    ),
)

CYBERPUNK_THEME = Theme(
    name="cyberpunk",
    display_name="Cyberpunk/Neon",
    is_dark=True,
    primary="#FF00FF",  # Magenta headers
    secondary="#00FFFF",  # Cyan
    accent="#FFFF00",  # Yellow
    background="#0D0221",  # Deep purple-black
    surface="#1A0A2E",  # Dark purple
    error="#FF3366",  # Hot pink
    warning="#FF9900",  # Orange
    success="#00FF9F",  # Neon green
    text="#F0F0F0",  # Off-white
    text_muted="#8B8B8B",  # Grey
    key_color="#00FFFF",  # Cyan keys (neon look)
    border_color="#FF00FF",  # Magenta border
    forensic_color="#00FF9F",  # Neon green
    malware_color="#FF3366",  # Hot pink
    security_color="#FFFF00",  # Yellow
    logo_color="#FF00FF",  # Magenta logo
    logo_text_color="#00FFFF",  # Cyan "Sandroid" text
    tool_color="#FF00FF",  # == primary, == this theme's .tool-tab.-active
    # color in themes/cyberpunk.tcss -- consistent with the chrome
    user_highlight_background="#2A1040",  # this theme's .tool-tab:hover bg --
    # already an established "lighter highlight" shade for this theme
    assistant_reply_color="#00FF9F",  # == success -- neon green, fits this
    # theme's neon aesthetic
    waiting_color="#FFCC00",  # neon amber -- distinct from this theme's
    # warning (#FF9900) and accent/security (#FFFF00)
    muted_status_color="#8B8B8B",  # == text_muted, == this theme's
    # .tool-tab inactive color -- consistent with the chrome
    lens=LensPalette(
        bg="#0D0221",
        panel="#1A0A2E",
        text="#F0F0F0",
        label="#B0A8C8",
        dim="#9A92B0",
        muted="#B0A8C8",
        title="#00FFFF",
        accent="#FF00FF",
        accent_text="#0D0221",
        ok="#00FF9F",
        warn="#FFCC00",
        bad="#FF3366",
        rule="#3A1660",
        rule_focus="#FF00FF",
        header="#9A92B0",
        cursor="#1A0A2E",
        cursor_focus="#3A1660",
        action_bg="#2A1040",
        action_text="#D0C8E0",
        action_hover_bg="#3A1660",
        action_hover_text="#00FFFF",
        input_bg="#1A0A2E",
        input_focus_bg="#2A1040",
        input_text="#F0F0F0",
        band="#1E0B3A",
        band_focus="#3A1660",
        stripe="#130630",
    ),
)

NORD_THEME = Theme(
    name="nord",
    display_name="Nord/Arctic",
    is_dark=True,
    primary="#88C0D0",  # Frost blue headers
    secondary="#81A1C1",  # Storm blue
    accent="#A3BE8C",  # Aurora green
    background="#2E3440",  # Polar night
    surface="#3B4252",  # Polar night lighter
    error="#BF616A",  # Aurora red
    warning="#EBCB8B",  # Aurora yellow
    success="#A3BE8C",  # Aurora green
    text="#ECEFF4",  # Snow storm
    text_muted="#4C566A",  # Polar night lightest
    key_color="#B48EAD",  # Aurora purple keys (Nord aurora)
    border_color="#4C566A",  # Polar night border
    forensic_color="#A3BE8C",  # Aurora green
    malware_color="#BF616A",  # Aurora red
    security_color="#EBCB8B",  # Aurora yellow
    logo_color="#88C0D0",  # Frost blue logo
    logo_text_color="#ECEFF4",  # Snow white "Sandroid" text
    tool_color="#88C0D0",  # == primary, == this theme's .tool-tab.-active
    # color in themes/nord.tcss -- consistent with the chrome
    user_highlight_background="#434C5E",  # this theme's .tool-tab:hover bg --
    # already an established "lighter highlight" shade for this theme
    assistant_reply_color="#A3BE8C",  # == success -- Nord's own aurora
    # green, already a soft/muted tone
    waiting_color="#D08770",  # Nord's own aurora orange (nord12) --
    # distinct from this theme's warning (#EBCB8B, aurora yellow)
    muted_status_color="#4C566A",  # == text_muted, == this theme's
    # .tool-tab inactive color -- consistent with the chrome
    lens=LensPalette(
        bg="#2E3440",
        panel="#3B4252",
        text="#ECEFF4",
        label="#A3ADC2",
        dim="#8892A6",
        muted="#A3ADC2",
        title="#88C0D0",
        accent="#88C0D0",
        accent_text="#2E3440",
        ok="#A3BE8C",
        warn="#EBCB8B",
        bad="#E0828A",
        rule="#4C566A",
        rule_focus="#88C0D0",
        header="#81A1C1",
        cursor="#3B4252",
        cursor_focus="#4C566A",
        action_bg="#434C5E",
        action_text="#D8DEE9",
        action_hover_bg="#4C566A",
        action_hover_text="#88C0D0",
        input_bg="#3B4252",
        input_focus_bg="#434C5E",
        input_text="#ECEFF4",
        band="#3B4252",
        band_focus="#4C566A",
        stripe="#323845",
    ),
)

DRACULA_THEME = Theme(
    name="dracula",
    display_name="Dracula",
    is_dark=True,
    primary="#BD93F9",  # Purple headers
    secondary="#6272A4",  # Comment blue
    accent="#50FA7B",  # Green
    background="#282A36",  # Background
    surface="#44475A",  # Current line
    error="#FF5555",  # Red
    warning="#FFB86C",  # Orange
    success="#50FA7B",  # Green
    text="#F8F8F2",  # Foreground
    text_muted="#6272A4",  # Comment
    key_color="#FF79C6",  # Pink keys (Dracula pink)
    border_color="#6272A4",  # Comment border
    forensic_color="#50FA7B",  # Green
    malware_color="#FF5555",  # Red
    security_color="#FFB86C",  # Orange
    logo_color="#BD93F9",  # Purple logo
    logo_text_color="#50FA7B",  # Green "Sandroid" text
    tool_color="#BD93F9",  # == primary, == this theme's .tool-tab.-active
    # color in themes/dracula.tcss -- consistent with the chrome
    user_highlight_background="#6272A4",  # this theme's .tool-tab:hover bg --
    # already an established "lighter highlight" shade for this theme
    assistant_reply_color="#50FA7B",  # == success -- Dracula's own green
    waiting_color="#FFB86C",  # == warning -- Dracula's canonical 8-color
    # palette has no second amber/orange distinct from this, so this is a
    # deliberate duplicate rather than an invented, non-canonical hex
    muted_status_color="#6272A4",  # == text_muted, == this theme's
    # .tool-tab inactive color -- consistent with the chrome
    lens=LensPalette(
        bg="#282A36",
        panel="#2F3240",
        text="#F8F8F2",
        label="#A9B1D6",
        dim="#8A93C0",
        muted="#A9B1D6",
        title="#BD93F9",
        accent="#8BE9FD",
        accent_text="#282A36",
        ok="#50FA7B",
        warn="#FFB86C",
        bad="#FF5555",
        rule="#44475A",
        rule_focus="#BD93F9",
        header="#8A93C0",
        cursor="#343746",
        cursor_focus="#4D5066",
        action_bg="#343746",
        action_text="#C8CCE0",
        action_hover_bg="#44475A",
        action_hover_text="#BD93F9",
        input_bg="#343746",
        input_focus_bg="#44475A",
        input_text="#F8F8F2",
        band="#323444",
        band_focus="#44475A",
        stripe="#2C2E3B",
    ),
)

SOLARIZED_THEME = Theme(
    name="solarized",
    display_name="Solarized Dark",
    is_dark=True,
    primary="#268BD2",  # Blue headers
    secondary="#2AA198",  # Cyan
    accent="#859900",  # Green
    background="#002B36",  # Base03
    surface="#073642",  # Base02
    error="#DC322F",  # Red
    warning="#B58900",  # Yellow
    success="#859900",  # Green
    text="#839496",  # Base0
    text_muted="#586E75",  # Base01
    key_color="#D33682",  # Magenta keys (Solarized magenta)
    border_color="#586E75",  # Base01 border
    forensic_color="#859900",  # Green
    malware_color="#DC322F",  # Red
    security_color="#B58900",  # Yellow
    logo_color="#2AA198",  # Cyan logo
    logo_text_color="#268BD2",  # Blue "Sandroid" text
    tool_color="#268BD2",  # == primary, == this theme's .tool-tab.-active
    # color in themes/solarized.tcss -- consistent with the chrome
    user_highlight_background="#073642",  # Base02 (== surface) -- one step
    # lighter than #chat-log's own background (Base03, #002B36); NOT this
    # theme's .tool-tab:hover bg, which is #002B36 -- identical to the log
    # background itself, i.e. zero contrast, so it would be invisible here
    assistant_reply_color="#859900",  # == success -- Solarized's own olive
    # green, already a muted tone
    waiting_color="#CB4B16",  # Solarized's own canonical "orange" swatch --
    # distinct from this theme's warning (#B58900, yellow)
    muted_status_color="#586E75",  # == text_muted, == this theme's
    # .tool-tab inactive color -- consistent with the chrome
    lens=LensPalette(
        bg="#002B36",
        panel="#073642",
        text="#93A1A1",
        label="#839496",
        dim="#6C8189",
        muted="#839496",
        title="#2AA198",
        accent="#268BD2",
        accent_text="#FDF6E3",
        ok="#859900",
        warn="#B58900",
        bad="#DC322F",
        rule="#244F5A",
        rule_focus="#268BD2",
        header="#6C8189",
        cursor="#073642",
        cursor_focus="#174E5C",
        action_bg="#073642",
        action_text="#93A1A1",
        action_hover_bg="#174E5C",
        action_hover_text="#FDF6E3",
        input_bg="#073642",
        input_focus_bg="#174E5C",
        input_text="#93A1A1",
        band="#063440",
        band_focus="#0E4A58",
        stripe="#03303B",
    ),
)


# ========== Dense-data dark themes ==========
# Three original dark themes for reading the App lens tables for hours. Same
# recipe for all three, so they differ in character, not in structure:
#
# * surfaces step up in small, even lightness steps:
#   lens ``bg`` < ``panel`` (spotlight head, log ticker) < chrome band
#   (header, status strip, lens tabs, footer) < ``cursor_focus``; the
#   unfocused ``cursor`` sits just above ``bg``.
# * text has three tiers: ``text`` (>= 12:1 on bg), ``label``/``muted``
#   (>= 7:1) and ``dim``/``header`` (>= 5:1 on bg, >= 4.5:1 even on the
#   focused cursor), so nothing the lens draws is below WCAG AA.
# * one accent hue, kept away from the ok/warn/bad hues; ok/warn/bad are
#   tuned to the surface but stay green/yellow/red.
# * the focused cursor keeps the cells' own colors (``cursor_keeps_colors``)
#   and the chrome's Textual variables (footer keys, scrollbars, OptionList
#   cursor) use the theme's colors instead of textual-dark's orange/blue.


def _dense_textual_variables(lens: LensPalette, band: str, scroll: str) -> dict:
    """Textual design variables for a dense-data dark theme."""
    return {
        "block-cursor-foreground": lens.text,
        "block-cursor-background": lens.cursor_focus,
        "block-cursor-blurred-foreground": lens.text,
        "block-cursor-blurred-background": lens.cursor,
        "block-hover-background": lens.cursor,
        "scrollbar": scroll,
        "scrollbar-hover": lens.dim,
        "scrollbar-active": lens.accent,
        "scrollbar-background": lens.bg,
        "scrollbar-background-hover": lens.bg,
        "scrollbar-background-active": lens.bg,
        "scrollbar-corner-color": lens.bg,
        "footer-background": band,
        "footer-foreground": lens.text,
        "footer-key-foreground": lens.title,
        "footer-description-foreground": lens.label,
    }


# Graphite: neutral charcoal, near-zero saturation, one copper accent.
GRAPHITE_LENS = LensPalette(
    bg="#1A1B1D",
    panel="#202124",
    text="#E8E6E1",
    label="#B5B2AB",
    dim="#A19E97",
    muted="#ABA8A1",
    title="#F0A15C",
    accent="#E8914A",
    accent_text="#1A1B1D",
    ok="#8FC77E",
    warn="#E6CD5A",
    bad="#F47A80",
    rule="#37393D",
    rule_focus="#E8914A",
    header="#A19E97",
    cursor="#1F2023",
    cursor_focus="#3E332C",
    action_bg="#27282C",
    action_text="#D2CFC8",
    action_hover_bg="#37393D",
    action_hover_text="#F0A15C",
    input_bg="#232427",
    input_focus_bg="#2D2E32",
    input_text="#E8E6E1",
    band="#26272B",
    band_focus="#35302A",
    stripe="#1E1F22",
    cursor_keeps_colors=True,
)

GRAPHITE_THEME = Theme(
    name="graphite",
    display_name="Graphite",
    is_dark=True,
    primary="#F0A15C",  # copper title
    secondary="#B5B2AB",  # warm grey label
    accent="#E8914A",  # copper focus
    background="#1A1B1D",  # charcoal
    surface="#202124",  # panel
    error="#F47A80",
    warning="#E6CD5A",
    success="#8FC77E",
    text="#E8E6E1",  # warm off-white
    text_muted="#ABA8A1",  # >= 6:1 on the chrome band
    key_color="#F0A15C",
    border_color="#37393D",
    forensic_color="#8FC77E",
    malware_color="#F47A80",
    security_color="#E6CD5A",
    logo_color="#E8914A",
    logo_text_color="#E8E6E1",
    tool_color="#C8A2E8",  # soft violet, apart from copper and the status hues
    user_highlight_background="#2D2E32",
    assistant_reply_color="#8FC77E",
    waiting_color="#F2B84B",
    muted_status_color="#A19E97",
    lens=GRAPHITE_LENS,
    textual_variables=_dense_textual_variables(GRAPHITE_LENS, "#27282C", "#45474C"),
)

# Deep Sea: blue-slate surfaces, a sea-glass cyan accent, lifted text.
DEEP_SEA_LENS = LensPalette(
    bg="#14202A",
    panel="#192631",
    text="#E3ECF4",
    label="#AABCCD",
    dim="#91A4B6",
    muted="#A0B3C5",
    title="#5CD0DA",
    accent="#3FBCC8",
    accent_text="#0D1820",
    ok="#86D68F",
    warn="#F2C063",
    bad="#F7878A",
    rule="#2B3D4E",
    rule_focus="#3FBCC8",
    header="#91A4B6",
    cursor="#182531",
    cursor_focus="#183A58",
    action_bg="#1E2D3B",
    action_text="#C9D6E2",
    action_hover_bg="#2B3D4E",
    action_hover_text="#5CD0DA",
    input_bg="#1A2733",
    input_focus_bg="#22334A",
    input_text="#E3ECF4",
    band="#1D2C3A",
    band_focus="#22405A",
    stripe="#17242F",
    cursor_keeps_colors=True,
)

DEEP_SEA_THEME = Theme(
    name="deep_sea",
    display_name="Deep Sea",
    is_dark=True,
    primary="#5CD0DA",  # sea-glass title
    secondary="#AABCCD",  # slate label
    accent="#3FBCC8",  # sea-glass focus
    background="#14202A",  # blue slate
    surface="#192631",
    error="#F7878A",
    warning="#F2C063",
    success="#86D68F",
    text="#E3ECF4",
    text_muted="#A0B3C5",  # >= 6:1 on the chrome band
    key_color="#5CD0DA",
    border_color="#2B3D4E",
    forensic_color="#86D68F",
    malware_color="#F7878A",
    security_color="#F2C063",
    logo_color="#3FBCC8",
    logo_text_color="#E3ECF4",
    tool_color="#B9A4F0",  # periwinkle, apart from cyan and the status hues
    user_highlight_background="#22334A",
    assistant_reply_color="#86D68F",
    waiting_color="#F5A962",
    muted_status_color="#91A4B6",
    lens=DEEP_SEA_LENS,
    textual_variables=_dense_textual_variables(DEEP_SEA_LENS, "#1E2D3B", "#344A5F"),
)

# Evergreen: warm moss-grey base, cream text, a heather (lilac) accent.
EVERGREEN_LENS = LensPalette(
    bg="#1A1F1B",
    panel="#1F2520",
    text="#EEE6D2",
    label="#BDB6A2",
    dim="#A5A08E",
    muted="#B2AB97",
    title="#CDAEE6",
    accent="#B99AD8",
    accent_text="#1A1F1B",
    ok="#98D27F",
    warn="#EAC55E",
    bad="#F08474",
    rule="#364036",
    rule_focus="#B99AD8",
    header="#A5A08E",
    cursor="#1F2520",
    cursor_focus="#283B23",
    action_bg="#252C25",
    action_text="#D6CFBC",
    action_hover_bg="#364036",
    action_hover_text="#CDAEE6",
    input_bg="#212721",
    input_focus_bg="#2B342B",
    input_text="#EEE6D2",
    band="#242B25",
    band_focus="#2F3D2C",
    stripe="#1D231E",
    cursor_keeps_colors=True,
)

EVERGREEN_THEME = Theme(
    name="evergreen",
    display_name="Evergreen",
    is_dark=True,
    primary="#CDAEE6",  # heather title
    secondary="#BDB6A2",  # parchment label
    accent="#B99AD8",  # heather focus
    background="#1A1F1B",  # moss grey
    surface="#1F2520",
    error="#F08474",
    warning="#EAC55E",
    success="#98D27F",
    text="#EEE6D2",  # cream
    text_muted="#B2AB97",  # >= 6:1 on the chrome band
    key_color="#CDAEE6",
    border_color="#364036",
    forensic_color="#98D27F",
    malware_color="#F08474",
    security_color="#EAC55E",
    logo_color="#98D27F",
    logo_text_color="#EEE6D2",
    tool_color="#8CC4E0",  # sky blue, apart from heather and the status hues
    user_highlight_background="#2B342B",
    assistant_reply_color="#98D27F",
    waiting_color="#F0A866",
    muted_status_color="#A5A08E",
    lens=EVERGREEN_LENS,
    textual_variables=_dense_textual_variables(EVERGREEN_LENS, "#252C25", "#424D41"),
)

# Theme registry
THEMES: dict[str, Theme] = {
    "default": DEFAULT_THEME,
    "dark": DARK_THEME,
    "light": LIGHT_THEME,
    "paper": PAPER_THEME,
    "daylight": DAYLIGHT_THEME,
    "high_contrast": HIGH_CONTRAST_THEME,
    "cyberpunk": CYBERPUNK_THEME,
    "nord": NORD_THEME,
    "dracula": DRACULA_THEME,
    "solarized": SOLARIZED_THEME,
    "graphite": GRAPHITE_THEME,
    "deep_sea": DEEP_SEA_THEME,
    "evergreen": EVERGREEN_THEME,
}

# Theme cycling order
THEME_ORDER = [
    "default",
    "dark",
    "light",
    "paper",
    "daylight",
    "high_contrast",
    "cyberpunk",
    "nord",
    "dracula",
    "solarized",
    "graphite",
    "deep_sea",
    "evergreen",
]


# ========== Theme Functions ==========


def get_theme(name: str) -> Theme:
    """Get a theme by name.

    Args:
        name: Theme identifier

    Returns:
        Theme instance, or default if not found
    """
    return THEMES.get(name, DEFAULT_THEME)


def get_next_theme(current: str) -> str:
    """Get the next theme in the cycle.

    Args:
        current: Current theme name

    Returns:
        Name of the next theme
    """
    try:
        idx = THEME_ORDER.index(current)
        return THEME_ORDER[(idx + 1) % len(THEME_ORDER)]
    except ValueError:
        return THEME_ORDER[0]


def get_previous_theme(current: str) -> str:
    """Get the previous theme in the cycle.

    Args:
        current: Current theme name

    Returns:
        Name of the previous theme
    """
    try:
        idx = THEME_ORDER.index(current)
        return THEME_ORDER[(idx - 1) % len(THEME_ORDER)]
    except ValueError:
        return THEME_ORDER[-1]


def get_all_themes() -> dict[str, Theme]:
    """Get all available themes.

    Returns:
        Dict mapping theme names to Theme instances
    """
    return THEMES.copy()


def theme_to_css_vars(theme: Theme) -> str:
    """Convert theme to Textual CSS variable definitions.

    Args:
        theme: Theme to convert

    Returns:
        CSS string with variable definitions
    """
    return f"""
$primary: {theme.primary};
$secondary: {theme.secondary};
$accent: {theme.accent};
$background: {theme.background};
$surface: {theme.surface};
$error: {theme.error};
$warning: {theme.warning};
$success: {theme.success};
$text: {theme.text};
$text-muted: {theme.text_muted};
$forensic-color: {theme.forensic_color};
$malware-color: {theme.malware_color};
$security-color: {theme.security_color};
$logo-color: {theme.logo_color};
$logo-text-color: {theme.logo_text_color};
"""


# ========== Textual themes + lens palette lookup ==========

#: Prefix of the Textual theme registered per Sandroid theme.
TEXTUAL_THEME_PREFIX = "sandroid-"


def textual_theme_name(theme_name: str) -> str:
    """Name of the Textual theme registered for Sandroid theme ``theme_name``."""
    return f"{TEXTUAL_THEME_PREFIX}{theme_name}"


def build_textual_theme(theme: Theme) -> TextualTheme:
    """The Textual theme carrying ``theme``'s lens tokens as CSS variables.

    It is a copy of ``textual-dark`` (or ``textual-light`` for a light theme)
    that ADDS the ``$lens-*`` variables, so Textual's own widgets (inputs,
    footers, scrollbars, ...) look exactly as they did when the app switched
    between those two built-in themes -- unless the theme sets
    ``textual_variables``, which override those base values.

    Args:
        theme: The Sandroid theme.

    Returns:
        A Textual theme named :func:`textual_theme_name` ``(theme.name)``.
    """
    base = BUILTIN_THEMES["textual-dark" if theme.is_dark else "textual-light"]
    return replace(
        base,
        name=textual_theme_name(theme.name),
        variables={
            **base.variables,
            **theme.textual_variables,
            **theme.lens.css_variables(),
        },
    )


def lens_css_defaults() -> dict[str, str]:
    """The ``$lens-*`` variables of the default theme (fallback values)."""
    return DEFAULT_LENS.css_variables()


def _active_theme() -> Theme | None:
    """The Sandroid theme of the running app (``None`` outside one of ours)."""
    try:
        name = active_app.get().theme
    except Exception:
        return None
    if not name.startswith(TEXTUAL_THEME_PREFIX):
        return None
    return THEMES.get(name[len(TEXTUAL_THEME_PREFIX) :])


def lens_palette() -> LensPalette:
    """The lens palette of the running app's current theme.

    Read at render time by the Rich styles built in Python, so a re-render
    after a theme change picks up the new colors. Outside a running app, or
    under a Textual theme that is not one of ours (a bare test ``App``), it
    is :data:`DEFAULT_LENS`.
    """
    theme = _active_theme()
    return theme.lens if theme is not None else DEFAULT_LENS


def fixed_color(name: str) -> str:
    """A :data:`FIXED_COLORS` entry as the running app's theme shows it.

    The dark themes all use :data:`FIXED_COLORS`; a light theme replaces
    entries with darker shades of the same hue (``Theme.status_colors``).
    Read at render time, like :func:`lens_palette`.
    """
    theme = _active_theme()
    if theme is not None and name in theme.status_colors:
        return theme.status_colors[name]
    return FIXED_COLORS[name]


# ========== CSS Path Functions ==========


def get_theme_css_path(theme_name: str) -> Path:
    """Get the path to a theme's CSS file.

    Args:
        theme_name: Name of the theme (default, dark, light, etc.)

    Returns:
        Path to the theme's CSS file
    """
    if theme_name == "default":
        # Default theme uses the main styles.tcss
        return PARENT_DIR / "styles.tcss"

    css_file = THEMES_DIR / f"{theme_name}.tcss"
    if css_file.exists():
        return css_file

    # Fall back to default if theme CSS doesn't exist
    return PARENT_DIR / "styles.tcss"


def get_available_theme_css_files() -> dict[str, Path]:
    """Get all available theme CSS files.

    Returns:
        Dict mapping theme names to their CSS file paths
    """
    themes = {
        "default": PARENT_DIR / "styles.tcss",
    }

    # Add all .tcss files in themes directory
    for css_file in THEMES_DIR.glob("*.tcss"):
        theme_name = css_file.stem
        themes[theme_name] = css_file

    return themes


# ========== Exports ==========
__all__ = [
    "CYBERPUNK_THEME",
    "DARK_THEME",
    "DEEP_SEA_THEME",
    "DAYLIGHT_THEME",
    "DEFAULT_LENS",
    "DEFAULT_THEME",
    "DRACULA_THEME",
    "EVERGREEN_THEME",
    "FIXED_COLORS",
    "GRAPHITE_THEME",
    "HIGH_CONTRAST_THEME",
    "LIGHT_THEME",
    "NORD_THEME",
    "PAPER_THEME",
    "PARENT_DIR",
    "SOLARIZED_THEME",
    "TEXTUAL_THEME_PREFIX",
    "THEMES",
    "THEMES_DIR",
    "THEME_ORDER",
    "LensPalette",
    "Theme",
    "build_textual_theme",
    "fixed_color",
    "get_all_themes",
    "get_available_theme_css_files",
    "get_next_theme",
    "get_previous_theme",
    "get_theme",
    "get_theme_css_path",
    "lens_css_defaults",
    "lens_palette",
    "textual_theme_name",
    "theme_to_css_vars",
]
