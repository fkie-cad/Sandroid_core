import json
import os
from logging import getLogger

from sandroid.core.adb import Adb
from sandroid.core.toolbox import Toolbox

from .datagather import DataGather

try:
    from dexray_insight import asam
except ImportError:
    logger = getLogger(__name__)
    logger.warning(
        "dexray-insight package not installed. Static analysis will be disabled."
    )
    asam = None

logger = getLogger(__name__)


class StaticAnalysis(DataGather):
    """Handles static analysis of APK files using dexray-insight (formerly ASAM)."""

    last_results = {}
    last_analysed_app = "no app name yet"

    def gather(self):
        """Gathers and analyzes the APK file of the spotlight application using dexray-insight.

        :raises Exception: If `asam` returns None or if there is an error during analysis.
        """
        if asam is None:
            logger.error("dexray-insight not available. Static analysis skipped.")
            self.last_results = {"error": "dexray-insight not installed"}
            return

        base_folder = os.getenv("RAW_RESULTS_PATH")
        apk_name = Toolbox.get_spotlight_application()[0]
        self.last_analysed_app = apk_name
        apk_path, stderr = Adb.send_adb_command("shell pm path " + apk_name)
        apk_path = apk_path[8:-1]
        logger.debug(
            f"running dexray-insight for {apk_name} located at {base_folder}{apk_name}.apk"
        )
        logger.info(
            "Statically analyzing spotlight App with dexray-insight. This might take a while."
        )
        Adb.send_adb_command(f"pull {apk_path} {base_folder}{apk_name}.apk")

        if os.path.exists(f"{base_folder}{apk_name}.apk"):
            try:
                # Use new dexray-insight API
                results, result_file_name, security_result_file_name = (
                    asam.start_apk_static_analysis(
                        apk_file_path=f"{base_folder}{apk_name}.apk",
                        do_signature_check=False,
                        apk_to_diff=None,
                        print_results_to_terminal=True,
                        is_verbose=False,
                        do_sec_analysis=True,  # Enable security analysis
                        exclude_net_libs=None,
                    )
                )

                if results is None:
                    raise Exception("dexray-insight returned None")

                # Convert results to dictionary for compatibility
                self.last_results = {
                    "analysis_results": results.to_dict(),
                    "json_output": results.to_json(),
                    "app_name": apk_name,
                    "result_files": {
                        "main_result": result_file_name,
                        "security_result": security_result_file_name,
                    },
                }

                logger.info(f"Static analysis completed successfully for {apk_name}")

            except Exception as e:
                logger.error("dexray-insight produced an error.")
                logger.error(
                    "This is not an issue with Sandroid. Empty output appended."
                )
                logger.error(str(e))
                self.last_results = {"error": str(e), "app_name": apk_name}

            # Clean up APK file
            try:
                os.remove(f"{base_folder}{apk_name}.apk")
            except OSError as e:
                logger.warning(f"Could not remove APK file: {e}")
        else:
            logger.error("Something went wrong pulling spotlight apk")
            self.last_results = {"error": "APK file not found", "app_name": apk_name}

    def return_data(self):
        """Returns the results of the last static analysis using dexray-insight.

        :returns: The results of the last static analysis.
        :rtype: dict
        """
        if not self.last_results:
            return {}

        # Return structured results from dexray-insight
        final_json = {self.last_analysed_app: self.last_results}
        return final_json

    def pretty_print(self):
        """Pretty prints the results of the last static analysis using dexray-insight."""
        if not self.last_results:
            print("No static analysis results available.")
            return

        if "error" in self.last_results:
            print(
                f"Static analysis error for {self.last_analysed_app}: {self.last_results['error']}"
            )
            return

        print(f"\n=== Static Analysis Results for {self.last_analysed_app} ===")

        # Print structured results from dexray-insight
        if "analysis_results" in self.last_results:
            analysis_data = self.last_results["analysis_results"]
            if isinstance(analysis_data, dict):
                for key, value in analysis_data.items():
                    if isinstance(value, (dict, list)):
                        print(f"{key}: {json.dumps(value, indent=2)}")
                    else:
                        print(f"{key}: {value}")
            else:
                print(f"Analysis results: {analysis_data}")

        if "result_files" in self.last_results:
            files = self.last_results["result_files"]
            print("\nResult files generated:")
            for file_type, file_path in files.items():
                if file_path:
                    print(f"  {file_type}: {file_path}")
