"""Hook registry for Frida-based analysis tools.

Provides centralized hook conflict detection, registration, and unregistration
with the Toolbox, extracted from MalwareMonitor to enable reuse.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class HookRegistry:
    """Manages Frida hook registration and conflict detection for an analysis tool.

    Wraps the common try/except pattern used by hook-related methods in
    MalwareMonitor (and potentially other tools) into a single class.

    Attributes:
        job_id: The virtual job ID used for hook registration.
        registered_hooks: List of hook names currently registered.
    """

    def __init__(self):
        self.job_id: str | None = None
        self.registered_hooks: list[str] = []

    def get_hooks_for_config(self, hook_config: dict[str, bool]) -> list[str]:
        """Get list of hooks based on the current hook configuration.

        Args:
            hook_config: Dictionary mapping hook category names to enabled/disabled.

        Returns:
            Combined list of native and Java hook names.
        """
        try:
            from sandroid.core.known_hooks import get_malwaremonitor_hooks_for_config

            native_hooks, java_hooks = get_malwaremonitor_hooks_for_config(hook_config)
            return native_hooks + java_hooks
        except ImportError:
            logger.debug("known_hooks module not available")
            return []
        except Exception as e:
            logger.debug(f"Could not get hooks for config: {e}")
            return []

    def check_conflicts(self, toolbox: Any, hook_config: dict[str, bool]) -> None:
        """Check for hook conflicts with other running Frida jobs and warn.

        Args:
            toolbox: The Toolbox instance for conflict checking.
            hook_config: Dictionary mapping hook category names to enabled/disabled.
        """
        try:
            all_hooks = self.get_hooks_for_config(hook_config)
            if not all_hooks:
                return

            conflicts = toolbox.check_frida_hook_conflicts(all_hooks)
            if conflicts:
                conflict_details = ", ".join(
                    f"{hook} (job: {job_id[:8]}...)"
                    for hook, job_id in conflicts.items()
                )
                logger.warning(
                    f"May conflict with existing Frida hooks: {conflict_details}"
                )

                enabled_categories = [k for k, v in hook_config.items() if v]
                logger.info(f"Enabled hook categories: {', '.join(enabled_categories)}")

            running_jobs = toolbox.get_running_frida_jobs()
            if running_jobs:
                job_names = [
                    j.get("display_name", j.get("job_type", "unknown"))
                    for j in running_jobs
                ]
                logger.info(
                    f"Note: Other Frida jobs are running: {', '.join(job_names)}"
                )

        except ImportError:
            logger.debug("known_hooks module not available for conflict detection")
        except Exception as e:
            logger.debug(f"Could not check for hook conflicts: {e}")

    def register_hooks(self, toolbox: Any, hook_config: dict[str, bool]) -> None:
        """Register hooks with Toolbox for conflict detection by other tools.

        Generates a virtual job ID and registers all enabled hooks.

        Args:
            toolbox: The Toolbox instance for hook registration.
            hook_config: Dictionary mapping hook category names to enabled/disabled.
        """
        try:
            import uuid

            self.job_id = f"malwaremonitor-{uuid.uuid4().hex[:8]}"
            self.registered_hooks = self.get_hooks_for_config(hook_config)

            if self.registered_hooks:
                toolbox.register_frida_hooks(self.job_id, self.registered_hooks)
                logger.debug(
                    f"Registered {len(self.registered_hooks)} hooks with Toolbox "
                    f"(job_id: {self.job_id})"
                )

        except ImportError:
            logger.debug("known_hooks module not available for hook registration")
        except Exception as e:
            logger.debug(f"Could not register hooks with Toolbox: {e}")

    def unregister_hooks(self, toolbox: Any) -> None:
        """Unregister hooks from Toolbox.

        Called when monitoring stops to clean up the hook registry.

        Args:
            toolbox: The Toolbox instance for hook unregistration.
        """
        try:
            if self.job_id and self.registered_hooks:
                toolbox.unregister_frida_hooks(self.job_id)
                logger.debug(
                    f"Unregistered {len(self.registered_hooks)} hooks from Toolbox "
                    f"(job_id: {self.job_id})"
                )

            self.registered_hooks = []

        except Exception as e:
            logger.debug(f"Could not unregister hooks from Toolbox: {e}")
