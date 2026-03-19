"""Interactive selection flows for App Selection Service.

Contains the CLI selection flow, fuzzy filtering operation, and shared
package-list fallback logic extracted from AppSelectionService.
"""

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _package_sort_key(pkg: dict[str, Any]) -> tuple[str, str]:
    """Sort key for ordering packages by install date (newest first), then name."""
    return (pkg.get("install_date") or "", pkg.get("package_name", ""))


def resolve_package_list(
    packages: list[str] | None,
    show_system: bool,
    prepare_fn: Callable[[list[str] | None, bool], list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], bool]:
    """Resolve and validate the package list, falling back to all packages.

    This unifies the duplicated fallback logic that was in both the TUI
    and CLI selection paths.

    Args:
        packages: Optional user-supplied package name list.
        show_system: Whether system apps are already included.
        prepare_fn: Callable that converts packages to dict format
                     (signature: ``(packages, show_system) -> list[dict]``).

    Returns:
        Tuple of (package_list, effective_show_system).
        *effective_show_system* may differ from *show_system* when a
        fallback to all packages was triggered.
    """
    pkg_list = prepare_fn(packages, show_system)

    if not pkg_list and not show_system and packages is None:
        logger.info("No user-installed packages found, falling back to all packages")
        pkg_list = prepare_fn(packages, True)
        show_system = True

    return pkg_list, show_system


# ---------------------------------------------------------------------------
# Fuzzy filter operation
# ---------------------------------------------------------------------------


class FuzzyFilterOperation:
    """Encapsulates fuzzy / substring filtering on package lists.

    This is a stateless helper that centralises the fuzzy-vs-simple
    decision and the ``thefuzz`` availability check.
    """

    def __init__(self) -> None:
        self._has_fuzzy: bool | None = None

    def is_available(self) -> bool:
        """Return True if ``thefuzz`` is importable (cached)."""
        if self._has_fuzzy is None:
            try:
                from thefuzz import fuzz, process

                self._has_fuzzy = True
            except ImportError:
                logger.debug(
                    "thefuzz library not available. Install with: pip install thefuzz"
                )
                self._has_fuzzy = False
        return self._has_fuzzy

    # -- dict-based filtering (package dicts) --------------------------------

    def filter_packages(
        self,
        query: str,
        packages: list[dict[str, Any]],
        min_score: int = 50,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Filter package dicts using fuzzy matching with simple fallback."""
        if self.is_available():
            return self._fuzzy_filter(query, packages, min_score, limit)
        return self._simple_filter(query, packages, limit)

    def _fuzzy_filter(
        self,
        query: str,
        packages: list[dict[str, Any]],
        min_score: int,
        limit: int,
    ) -> list[dict[str, Any]]:
        try:
            from thefuzz import fuzz, process

            package_names = [p.get("package_name", "") for p in packages]
            matches = process.extract(
                query,
                package_names,
                scorer=fuzz.partial_ratio,
                limit=limit,
            )

            result: list[dict[str, Any]] = []
            for match_name, score in matches:
                if score >= min_score:
                    for pkg in packages:
                        if pkg.get("package_name") == match_name:
                            result.append(pkg)
                            break
            return result

        except ImportError:
            logger.warning("Fuzzy search unavailable, using simple filter")
            return self._simple_filter(query, packages, limit)

    @staticmethod
    def _simple_filter(
        query: str,
        packages: list[dict[str, Any]],
        limit: int,
    ) -> list[dict[str, Any]]:
        query_lower = query.lower()
        return [
            p for p in packages if query_lower in p.get("package_name", "").lower()
        ][:limit]

    # -- string-based filtering (package names only) -------------------------

    def filter_names(
        self,
        query: str,
        names: list[str],
        min_score: int = 50,
        limit: int = 20,
    ) -> list[str]:
        """Filter plain package-name strings."""
        if self.is_available():
            try:
                from thefuzz import fuzz, process

                matches = process.extract(
                    query,
                    names,
                    scorer=fuzz.partial_ratio,
                    limit=limit,
                )
                return [m[0] for m in matches if m[1] >= min_score]
            except ImportError:
                pass
        query_lower = query.lower()
        return [p for p in names if query_lower in p.lower()][:limit]


# ---------------------------------------------------------------------------
# CLI selection flow
# ---------------------------------------------------------------------------


class CLISelectionFlow:
    """Interactive CLI app selection using Rich console and click.

    Broken into small, focused methods so each step is independently
    testable.

    Args:
        fuzzy_op: A ``FuzzyFilterOperation`` instance (shared with the
                  owning service so the availability cache is reused).
        filter_packages_fn: Callback to run full filter_packages on the
                            service (``AppSelectionService.filter_packages``).
    """

    def __init__(
        self,
        fuzzy_op: FuzzyFilterOperation,
        filter_packages_fn: Callable[[str, list[dict[str, Any]]], list[dict[str, Any]]],
    ) -> None:
        self._fuzzy = fuzzy_op
        self._filter_packages = filter_packages_fn

    # -- public entry point --------------------------------------------------

    def run(
        self,
        pkg_list: list[dict[str, Any]],
        show_system: bool,
        recently_installed_package: str | None,
    ) -> str | None:
        """Execute the full CLI selection flow.

        Returns the selected package name or ``None`` if cancelled.
        """
        try:
            import click

            from sandroid.core.formatting import SandroidConsole

            console = SandroidConsole.get()
            has_fuzzy = self._fuzzy.is_available()

            # 1. Recently-installed shortcut
            if recently_installed_package:
                picked = self._offer_recent(console, recently_installed_package)
                if picked is not None:
                    return picked

            # 2. Guard: empty list
            if not pkg_list:
                logger.error("No packages found on device")
                return None

            # 3. Sort and display
            pkg_list.sort(key=_package_sort_key, reverse=True)
            filtered = pkg_list

            app_type = "User-Installed" if not show_system else "All"
            console.print(
                f"\n[menu.section]=== {app_type} Applications "
                f"({len(filtered)}) ===[/menu.section]"
            )
            self._display_packages(console, filtered, show_system)

            # 4. Single-app shortcut
            if len(filtered) == 1:
                return self._handle_single(console, filtered)

            # 5. Selection loop
            return self._selection_loop(
                console,
                pkg_list,
                filtered,
                show_system,
                has_fuzzy,
            )

        except Exception as e:
            logger.error(f"Error during CLI app selection: {e}")
            return None

    # -- step helpers --------------------------------------------------------

    @staticmethod
    def _offer_recent(console: Any, package: str) -> str | None:
        """Offer recently installed package; return it if accepted."""
        import click

        console.print("\n[menu.section]=== Recently Installed App ===[/menu.section]")
        console.print(
            f"[warning]\\[0][/warning] [success]{package}[/success] "
            f"[primary](Just installed)[/primary]"
        )
        console.print(
            "\n[warning]Press 0 to use this app, or press ENTER "
            "to see all apps:[/warning]"
        )
        try:
            char = click.getchar()
            if char == "0":
                logger.info(f"Selected recently installed app: {package}")
                return package
        except (KeyboardInterrupt, EOFError):
            pass
        return None

    @staticmethod
    def _handle_single(
        console: Any,
        filtered: list[dict[str, Any]],
    ) -> str | None:
        console.print(
            "\n[success]Press Enter to select this app, or 'q' to cancel:[/success] ",
            end="",
        )
        choice = _safe_input("")
        if choice.lower() != "q":
            return filtered[0]["package_name"]
        return None

    def _selection_loop(
        self,
        console: Any,
        all_packages: list[dict[str, Any]],
        filtered: list[dict[str, Any]],
        show_system: bool,
        has_fuzzy: bool,
    ) -> str | None:
        while True:
            try:
                if has_fuzzy and filtered is all_packages:
                    prompt = (
                        f"\nEnter number (1-{len(filtered)}), "
                        "'f' to filter, or 'q' to cancel: "
                    )
                else:
                    prompt = f"\nEnter number (1-{len(filtered)}) or 'q' to cancel: "

                selection_input = _safe_input(prompt)

                if selection_input.lower() == "q":
                    logger.info("Selection cancelled")
                    return None

                if selection_input.lower() == "f" and has_fuzzy:
                    filtered = self._apply_fuzzy_filter(
                        console,
                        all_packages,
                        filtered,
                        show_system,
                    )
                    continue

                selected_idx = int(selection_input)
                if 1 <= selected_idx <= len(filtered):
                    selected = filtered[selected_idx - 1]["package_name"]
                    logger.info(f"Selected: {selected}")
                    return selected

                console.print(
                    f"[error]Invalid number. Please enter 1-{len(filtered)}[/error]"
                )

            except ValueError:
                if has_fuzzy and filtered is all_packages:
                    console.print(
                        "[error]Invalid input. Please enter a number, "
                        "'f' to filter, or 'q'[/error]"
                    )
                else:
                    console.print(
                        "[error]Invalid input. Please enter a number or 'q'[/error]"
                    )
            except KeyboardInterrupt:
                logger.info("\nSelection cancelled by user")
                return None

    def _apply_fuzzy_filter(
        self,
        console: Any,
        all_packages: list[dict[str, Any]],
        current_packages: list[dict[str, Any]],
        show_system: bool,
    ) -> list[dict[str, Any]]:
        console.print("\n[menu.section]=== Fuzzy Search Filter ===[/menu.section]")
        search_term = _safe_input("Enter search term (or press ENTER to show all): ")

        if search_term:
            filtered = self._filter_packages(search_term, all_packages)
            if not filtered:
                logger.warning(
                    f"No matches found for '{search_term}'. Showing all apps."
                )
                filtered = all_packages
        else:
            filtered = all_packages

        app_type = "User-Installed" if not show_system else "All"
        console.print(
            f"\n[menu.section]=== {app_type} Applications "
            f"({len(filtered)}) ===[/menu.section]"
        )
        self._display_packages(console, filtered, show_system)
        return filtered

    @staticmethod
    def _display_packages(
        console: Any,
        packages: list[dict[str, Any]],
        show_system: bool,
    ) -> None:
        for idx, pkg in enumerate(packages, 1):
            install_date = pkg.get("install_date", "Unknown")
            pkg_name = pkg.get("package_name", "")

            if len(pkg_name) > 50:
                pkg_name = pkg_name[:47] + "..."

            type_indicator = ""
            if show_system and pkg.get("is_user_app", False):
                type_indicator = " [info]\\[USER][/info]"

            console.print(
                f"[warning]{idx:3d}.[/warning] "
                f"[success]{pkg_name:50s}[/success]"
                f"{type_indicator} "
                f"[primary]\\[{install_date}][/primary]"
            )

            if idx % 20 == 0 and idx < len(packages):
                response = _safe_input(
                    "\nPress ENTER to see more, or type a number to select: "
                )
                if response.isdigit():
                    selected_idx = int(response)
                    if 1 <= selected_idx <= len(packages):
                        return


# ---------------------------------------------------------------------------
# Module-level utility
# ---------------------------------------------------------------------------


def _safe_input(prompt: str) -> str:
    """Safe input that handles EOFError."""
    try:
        return input(prompt)
    except EOFError:
        return ""
