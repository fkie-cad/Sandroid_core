from __future__ import annotations

import os
import asyncio
import sys
import json
import time
import requests
from typing import Optional, Dict, Any, List, Literal
from datetime import datetime
from dataclasses import dataclass
from contextlib import contextmanager
from logging import getLogger
from sandroid.config import ConfigLoader, SandroidConfig
from sandroid.core.toolbox import Toolbox

# Third-party imports (optional)
try:  # dotenv is optional
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    load_dotenv = None

from pydantic import BaseModel, Field

AI_DEPENDENCIES_AVAILABLE = False
AI_IMPORT_ERROR: Optional[Exception] = None

try:
    from pydantic_ai import Agent, RunContext
    from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded
    from pydantic_ai.messages import (
        ModelMessage,
        AgentStreamEvent,
        FinalResultEvent,
        FunctionToolCallEvent,
        FunctionToolResultEvent,
        PartDeltaEvent,
        PartStartEvent,
        TextPartDelta,
    )
    AI_DEPENDENCIES_AVAILABLE = True
except ImportError as exc:  # pragma: no cover - optional dependency
    AI_IMPORT_ERROR = exc

import warnings
warnings.filterwarnings("ignore", message="`additionalProperties` is not supported by Gemini")

# Load environment variables
if load_dotenv:
    load_dotenv()

logger = getLogger(__name__)

# ============================================================================
# CONFIGURATION AND DATA MODELS
# ============================================================================

@dataclass
class AgentConfig:
    """Configuration for the AI agent derived from project settings."""

    provider: str = "google-gla"
    model: str = "gemini-2.5-flash"

    @property
    def model_name(self) -> str:
        """Return provider/model identifier expected by pydantic-ai."""
        return f"{self.provider}:{self.model}"

    @classmethod
    def from_project_config(cls, config: Optional[SandroidConfig] = None) -> "AgentConfig":
        """Create configuration backed by the project's configuration files."""
        resolved_config = config

        if resolved_config is None and hasattr(Toolbox, "config") and Toolbox.config:
            resolved_config = Toolbox.config

        if resolved_config is None:
            resolved_config = ConfigLoader().load()

        ai_config = resolved_config.ai

        if ai_config.agent_model:
            provider = ai_config.agent_provider or ai_config.VIDEO_PROVIDER
            model = ai_config.agent_model
        else:
            provider = ai_config.VIDEO_PROVIDER
            model = ai_config.video_model

        return cls(provider=provider, model=model)

    @classmethod
    def from_env(cls, config: Optional[SandroidConfig] = None) -> "AgentConfig":
        """Backward-compatible alias that now reads from project configuration."""
        return cls.from_project_config(config)


class TaskResult(BaseModel):
    """Structured output for the initial task"""
    success: bool = Field(description="Whether the task was completed successfully")
    result: str = Field(description="A short explanation of your findings, including any context, observations, caveats or fun facts the user should know")
    # artifacts: List[str] = Field(description="List of the top artifacts created by the action on the device, sorted by value. Highest value first.")
    steps_taken: List[str] = Field(description="List of steps or actions taken during task execution")
    metadata: Dict[str, str] = Field(default_factory=dict, description="Additional metadata about the task")


@dataclass 
class AgentDependencies:
    """Dependencies that can be injected into the agent context"""
    config: AgentConfig
    task_context: Dict[str, Any]
    progress_callback: Optional[callable] = None

    def log_progress(self, message: str, step: int = None):
        """Log progress with optional callback"""
        if self.progress_callback:
            self.progress_callback(message, step)
        else:
            timestamp = datetime.now().strftime("%H:%M:%S")
            if step is not None:
                logger.info(f"[{timestamp}] Step {step}: {message}")
            else:
                logger.info(f"[{timestamp}] {message}")
        time.sleep(5) # Artificial delay to avoid rate limits


# ============================================================================
# AGENT IMPLEMENTATION
# ============================================================================

class AIAgentSystem:
    """Main AI Agent System plus chat capabilities"""

    def __init__(self, config: Optional[AgentConfig] = None):
        if not AI_DEPENDENCIES_AVAILABLE:
            raise RuntimeError(
                "AI features are unavailable because optional dependency 'pydantic-ai' "
                "is not installed. Install Sandroid with the 'ai' extra (pip install "
                "\"sandroid[ai]\") to enable this component."
            ) from AI_IMPORT_ERROR

        self.config = config or AgentConfig.from_project_config()
        self.initial_task_completed = False
        self.task_result: Optional[TaskResult] = None
        self.conversation_history: List[ModelMessage] = []
        self.artifacts = []

        # Initialize the agent
        self._init_agent()

    def _init_agent(self):
        """Initialize the Pydantic AI agent with configuration"""
        try:
            system_prompt = self._get_system_prompt()

            # Create agent for initial task processing
            self.task_agent = Agent[AgentDependencies, TaskResult](
                model=self.config.model_name,
                deps_type=AgentDependencies,
                output_type=TaskResult,
                instructions=system_prompt
            )

            # Create agent for chat interface (no structured output)
            self.chat_agent = Agent[AgentDependencies, str](
                model=self.config.model_name,
                deps_type=AgentDependencies,
                output_type=str,
                instructions=self._get_chat_instructions()
            )

            # Register tools on both agents
            self._register_tools()
            logger.info(f"AI Agent initialized. Using {self.config.model_name}")

        except Exception as e:
            print(f"Error initializing agent: {e}")
            #print("Falling back to default Gemini model...")
            #self.config.provider = "google-gla"
            #self.config.model = "gemini-2.5-flash"
            #self._init_agent()

    def _get_system_prompt(self) -> str:
        return """
You are an advanced AI agent meant to assist a professional cyber security researcher in finding forensic artifacts for a given action on an Android device. You are part of the Sandroid Toolkit.

You are given:
- Access to a ground truth representing all actions that were taken on the device as well as additional details that might or might not be relevant. Ground truth timestamps generally do not match up with Artifact timestamps because the replaying is slower than the recording (eg. user adds contact 10 seconds into the recording, the contact file artefact might be marked as being created 13 seconds after start of action)
- The output from previous stages of the Sandroid Toolkit that has already analyzed this action to distill down what changes in the file system occurred as a result. Most but likely not all noise has been removed.
- A number of tools that allow you to read additional raw data that was collected by Sandroid

Your task is to correlate these two main pieces of data the Ground truth and the Sandroid output, in order to detect, prioritize and finally submit forensic artifacts. This should create deeper insight for the user, eliminate noise further, and make their life finding the best artifacts easier.

"Artifacts" are defined as any change made to the file system as a result of an action a user took. Some artifacts are more "valuable" than others.
Some aspects that make an Artifact more valuable are:
1. It likely persists over time in the file system after the action is over
2. It directly identifies the action that caused it
3. It contains relevant human readable data such as text from an sms or a recipient phone number
4. It includes a timestamp identifying the time the action was taken
Report the best Artifacts in an ordered list as short as possible but as long as necessary.
If multiple significant actions were taken by the user, try to assign artifacts to the specific action they belong to.

How Sandroid works:
Fundamentally, Sandroid works by recording a user action and then replaying it multiple times to create diffs of files by checking in the filesystem which files where changed during the action.
This is done at least twice, files that changed during the replays are pulled, the version from before the action is saved in the first_pull and the version from after the action in the second_pull directories.
By looking at creation timestamps Sandroid can also see if a file was created between the action starting and ending. These new files are also pulled and saved in the new_pull directory.
This approach can be applied to a variety of other artifact types like network, running processes, sockets, deleted files and so on. These are only kept track of if the user activated the relevant flags. While some of these like network also generate files in the raw result folder, all the found artifacts are always represented in the sandroid output itself.
Sandroid generally only considers an artifact as confirmed if it appears in all repeats of the action.
The main method to filter out noise is the "Dry Run" in sandroid. Here the phone is reset to the state right before the action, as if the action would be replayed, but then the program just waits. Any files that still change are then excluded from the results. these dry run files are also pulled and available.
For database and xml files, the specific changes inside the file are analyzed, such that even if a db is updated by the action and by an unrelated background process, only the relevant changes are reported as artifacts.
If you have a specific reason, you can look into these files to double check Sandroid results, or investigate a specific hypothesis. Only do this if it is really necessary, as these files can be very large and overwhelm your context window.

Additional Instructions:
1. Create a step by step plan on how you want to approach the task.
2. Call tools as necessary to gather information and look more deeply into specific artifacts.
3. Change your approach and focus based on the information gathered if needed.
4. Document each step you are taking with the log_step tool.
5. Use clear, concise language. Use technical language.
6. If there are multiple actions present in the ground truth, assign artifacts to the specific action they belong to. Do a full complete analysis for each action.
7. Once you have found, confirmed and rated and artifact, use the submit_artifact tool and move on to the next until the task is complete.
"""

    def _get_chat_instructions(self) -> str:
        return """
You have completed the initial forensic analysis task. You are now in chat mode with the user.

You can:
1. Answer questions about the analysis results
2. Provide clarifications or additional details  
3. Use available tools to gather more information and continue the analysis

Be helpful and reference the initial task results when relevant.

Writing style: Very short and practical, robot-like, matter-of-fact. The user is not here to have a conversation, they are working. No prose.

As a reminder, "Artifacts" are defined as any change made to the file system as a result of an action a user took. Some artifacts are more "valuable" than others.
Some aspects that make an Artifact more valuable are:
1. It likely persists over time in the file system after the action is over
2. It directly identifies the action that caused it
3. It contains relevant human readable data such as text from an sms or a recipient phone number
4. It includes a timestamp identifying the time the action was taken
"""
    def _get_sandroid_results(self) -> str:
        """Read and return the contents of the sandroid results file"""
        results_path = f'{os.getenv("RESULTS_PATH")}sandroid.json'
        try:
            with open(results_path, 'r') as f:
                return f'These are {f.read()}'
        except FileNotFoundError:
            return "Sandroid results file not found."
        except Exception as e:
            return f"Error reading sandroid results: {e}"

    def _register_tools(self):
        """
        Add tool functions that the agent can call to enhance its capabilities.
        Tools can access external APIs, databases, files, etc.
        """

        @self.task_agent.tool
        @self.chat_agent.tool  # Register on both agents
        async def get_current_time(ctx: RunContext[AgentDependencies]) -> str:
            """Get the current date and time."""
            ctx.deps.log_progress(" ⚙️  Agent using tool: Get current time")
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        @self.task_agent.tool
        @self.chat_agent.tool
        async def translate_unix_timestamp(ctx: RunContext[AgentDependencies], timestamp: int) -> str:
            """Translate a Unix timestamp to a human-readable date."""
            ctx.deps.log_progress(f" ⚙️  Agent using tool: Translating timestamp {timestamp}")
            return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        
        @self.task_agent.tool
        @self.chat_agent.tool
        async def get_action_time(ctx: RunContext[AgentDependencies]) -> str:
            """Returns the time and duration of the action the user performed on the emulator."""
            ctx.deps.log_progress(" ⚙️  Agent using tool: Get action time")
            return f'Unix timestamp of action: {Toolbox.get_action_time()}, the action took {Toolbox.get_action_duration()} seconds'
        
        @self.task_agent.tool
        @self.chat_agent.tool
        async def correlate_timestamp(ctx: RunContext[AgentDependencies], timestamp: int) -> str:
            """Calculates if the given unix timestamp falls within the action time window. Use this function to avoid having to do multiple calls and calculations yourself."""
            ctx.deps.log_progress(f" ⚙️  Agent using tool: Correlate timestamp {timestamp} with action time")
            action_time = Toolbox.get_action_time()
            action_duration = Toolbox.get_action_duration()
            if action_time <= timestamp <= (action_time + action_duration):
                return f'The timestamp {timestamp} falls within the action time window. ({timestamp - action_time} seconds after action start)'
            elif timestamp - action_time < 0:
                return f'The timestamp {timestamp} falls BEFORE the action time window. ({action_time - timestamp} seconds before action start)'
            else:
                return f'The timestamp {timestamp} falls AFTER the action time window. ({timestamp - (action_time + action_duration)} seconds after action end)'

        @self.task_agent.tool
        @self.chat_agent.tool
        async def artifact_definition(ctx: RunContext[AgentDependencies]) -> str:
            """Repeats the definition of an artifact and a short guide on how to determine artifact value."""
            return """
"Artifacts" are defined as any change made to the file system as a result of an action a user took. Some artifacts are more "valuable" than others.
Some aspects that make an Artifact more valuable are:
1. It likely persists over time in the file system after the action is over
2. It directly identifies the action that caused it
3. It contains relevant human readable data such as text from an sms or a recipient phone number
4. It includes a timestamp identifying the time the action was taken
"""

        @self.task_agent.tool
        @self.chat_agent.tool
        async def sandroid_background(ctx: RunContext[AgentDependencies]) -> str:
            """Repeats the description of the internal workings of Sandroid, in case they are needed for context again."""
            return """
How Sandroid works:
Fundamentally, Sandroid works by recording a user action and then replaying it multiple times to create diffs of files by checking in the filesystem which files where changed during the action.
This is done at least twice, files that changed during the replays are pulled, the version from before the action is saved in the first_pull and the version from after the action in the second_pull directories.
By looking at creation timestamps Sandroid can also see if a file was created between the action starting and ending. These new files are also pulled and saved in the new_pull directory.
This approach can be applied to a variety of other artifact types like network, running processes, sockets, deleted files and so on. These are only kept track of if the user activated the relevant flags. While some of these like network also generate files in the raw result folder, all the found artifacts are always represented in the sandroid output itself.
Sandroid generally only considers an artifact as confirmed if it appears in all repeats of the action.
The main method to filter out noise is the "Dry Run" in sandroid. Here the phone is reset to the state right before the action, as if the action would be replayed, but then the program just waits. Any files that still change are then excluded from the results. these dry run files are also pulled and available.
For database and xml files, the specific changes inside the file are analyzed, such that even if a db is updated by the action and by an unrelated background process, only the relevant changes are reported as artifacts.
If you have a specific reason, you can look into these files to double check Sandroid results, or investigate a specific hypothesis. Only do this if it is really necessary, as these files can be very large and overwhelm your context window.
"""

        @self.task_agent.tool
        @self.chat_agent.tool
        async def get_full_sandroid_output(ctx: RunContext[AgentDependencies]) -> str:
            """Returns the full, uncropped Sandroid output. Only read this if it is absolutely necessary to read parts that were cropped out in the summary. This file can be very large and overwhelm your context window."""
            ctx.deps.log_progress(" ⚙️  Agent using tool: Read full Sandroid output")
            results_path = os.path.join(os.getenv('RESULTS_PATH', ''), 'sandroid.json')
            try:
                with open(results_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            except FileNotFoundError:
                return f"Error: File not found at path: {results_path}"
            except Exception as e:
                return f"Error reading file at path {results_path}: {e}"

        @self.task_agent.tool
        @self.chat_agent.tool
        async def log_step(
            ctx: RunContext[AgentDependencies], 
            step_description: str,
            step_number: Optional[int] = None
        ) -> str:
            """Log a step in the task processing."""
            ctx.deps.log_progress(step_description, step_number)
            return f"Step logged: {step_description}"
    
        
        @self.task_agent.tool
        @self.chat_agent.tool
        async def read_result_file(ctx: RunContext[AgentDependencies], path: str) -> str:
            """Read any of the raw result files generated by Sandroid. This also includes most files that were identified as containing artifacts. 
            To see which files are available, read the folder structure first, then provide the relative path. Example: changed files can be found under raw/(first_pull or second pull)/(path seen in sandroid output). 
            Read files sparingly to not waste tokens. Use the 'search_in_file' tool instead when feasible."""
            ctx.deps.log_progress(f" ⚙️  Agent using tool: Reading file {path}")
            base_path = os.getenv('RESULTS_PATH')
            path = path.lstrip('/')

            # Prevent path traversal attacks
            full_path = os.path.abspath(os.path.join(base_path, path))
            if not full_path.startswith(os.path.abspath(base_path)):
                return "Error: Access denied. Path is outside the allowed directory."

            try:
                # Check file size before reading to avoid context overload
                file_size = os.path.getsize(full_path)
                if file_size > 100000:  # 100KB limit
                    return f"Error: File '{path}' is too large ({file_size} bytes). Use the 'search_in_file' tool to search for specific content instead of reading the whole file."

                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            except FileNotFoundError:
                return f"Error: File not found at path: {path}"
            except Exception as e:
                return f"Error reading file at path {path}: {e}"
        
        @self.task_agent.tool
        @self.chat_agent.tool
        async def search_in_file(ctx: RunContext[AgentDependencies], path: str, search_terms: list[str]) -> str:
            """Search for any of the provided strings in file specified by path. This is more efficient than reading the full file if you are looking for specific information.
            Use search liberally, search for multiple short terms at once to increase chances of a hit.
            If a promising file returns no hits, consider reading it fully with the read_result_file tool."""
            ctx.deps.log_progress(f" ⚙️  Agent using tool: Searching {path} for these terms: {', '.join(search_terms)}")
            base_path = os.getenv('RESULTS_PATH')
            path = path.lstrip('/')

            # Prevent path traversal attacks
            full_path = os.path.abspath(os.path.join(base_path, path))
            if not full_path.startswith(os.path.abspath(base_path)):
                return "Error: Access denied. Path is outside the allowed directory."

            try:
                import subprocess
                all_results = []
                
                for term in search_terms:
                    try:
                        # Use grep to search for the term (case-insensitive with line numbers), treating binary files as text
                        result = subprocess.run(
                            ['grep', '-a', '-i', '-n', term, full_path],
                            capture_output=True,
                            text=True,
                            encoding='utf-8',
                            errors='ignore'
                        )
                        
                        if result.returncode == 0 and result.stdout.strip():
                            all_results.append(f"=== Results for '{term}' ===")
                            all_results.append(result.stdout.strip())
                        elif result.returncode == 1:
                            # grep returns 1 when no matches found (not an error)
                            all_results.append(f"=== Results for '{term}' ===")
                            all_results.append("No matches found")
                        else:
                            # Other error codes indicate actual errors
                            all_results.append(f"=== Results for '{term}' ===")
                            all_results.append(f"Error searching for term: {result.stderr.strip()}")
                            
                    except subprocess.SubprocessError as e:
                        all_results.append(f"=== Results for '{term}' ===")
                        all_results.append(f"Subprocess error: {e}")
                
                if not all_results:
                    return "No search results found for any terms"
                
                return "\n".join(all_results)
                
            except FileNotFoundError:
                return f"Error: File not found at path: {path}"
            except Exception as e:
                return f"Error searching file at path {path}: {e}"
        
        @self.task_agent.tool
        @self.chat_agent.tool
        async def search_all_artifact_files(ctx: RunContext[AgentDependencies], search_term: str) -> str:
            """Search all files that were pulled by Sandroid for a specific term using grep. Includes the old and new version of files that changed during the action, pcap files, and more. Use for more exploratory searches."""
            ctx.deps.log_progress(f" ⚙️  Agent using tool: Searching all pulled files for search term: {search_term}")
            base_path = os.getenv('RAW_RESULTS_PATH')
            
            if not base_path:
                return "Error: RAW_RESULTS_PATH environment variable is not set."
            
            try:
                import subprocess
                results_dict = {}
                
                # Walk through all files recursively
                for root, dirs, files in os.walk(base_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, base_path)
                        
                        try:
                            # Use grep to search for the term (case-insensitive with line numbers), treating binary files as text
                            result = subprocess.run(
                                ['grep', '-a', '-i', '-n', search_term, file_path],
                                capture_output=True,
                                text=True,
                                encoding='utf-8',
                                errors='ignore'
                            )
                            
                            # Only add to results if matches were found
                            if result.returncode == 0 and result.stdout.strip():
                                results_dict[relative_path] = result.stdout.strip()
                                
                        except subprocess.SubprocessError:
                            # Skip files that can't be searched (binary files, etc.)
                            continue
                        except Exception:
                            # Skip any problematic files
                            continue
                
                if not results_dict:
                    return f"No matches found for '{search_term}' in any artifact files."
                
                # Format the results as a readable string
                formatted_results = [f"Search results for '{search_term}':"]
                for file_path, matches in results_dict.items():
                    formatted_results.append(f"\n=== {file_path} ===")
                    formatted_results.append(matches)
                
                return "\n".join(formatted_results)
                
            except Exception as e:
                return f"Error searching artifact files: {e}"
        
        @self.task_agent.tool
        @self.chat_agent.tool
        async def see_available_result_files(ctx: RunContext[AgentDependencies]) -> str:
            """List all available Sandroid output and artifact files in a tree-like format."""
            ctx.deps.log_progress(f" ⚙️  Agent using tool: Listing tree structure of output folder")
            base_path = os.getenv('RESULTS_PATH')
            if not base_path:
                return "Error: RESULTS_PATH environment variable is not set."

            try:
                tree = []
                for root, dirs, files in os.walk(base_path):
                    level = root.replace(base_path, '').count(os.sep)
                    indent = ' ' * 4 * (level)
                    
                    relative_path = os.path.relpath(root, base_path)
                    if relative_path == ".":
                        tree.append("Available result files:")
                    else:
                        tree.append(f"{indent}└── {os.path.basename(root)}/")

                    sub_indent = ' ' * 4 * (level + 1)
                    for f in files:
                        try:
                            file_path = os.path.join(root, f)
                            file_size = os.path.getsize(file_path)
                            tree.append(f"{sub_indent}├── {f} ({file_size} bytes)")
                        except OSError:
                            tree.append(f"{sub_indent}├── {f} (size unknown)")
                return "\n".join(tree)
            except Exception as e:
                return f"Error reading result files: {e}"


        @self.task_agent.tool
        @self.chat_agent.tool
        async def get_artifacts_at_time(ctx: RunContext[AgentDependencies], seconds_after_start: int, confirmed_results_only: bool = True) -> str:
            """Returns all files that changed or were created at the specific time offset from the start of the action given by seconds_after_start. 
            Returns files from both all runs.
            Use this tool to assign artifacts to actions when there are multiple actions in one recording.
            If confirmed_results_only is true, only returns files that were confirmed as artifacts by Sandroid, otherwise, all files are returned."""
            ctx.deps.log_progress(f" ⚙️  Agent using tool: Listing artifacts generated {seconds_after_start} seconds after start")
            
            try:

                # Read sandroid.json
                results_path = os.path.join(os.getenv('RESULTS_PATH', ''), 'sandroid.json')
                with open(results_path, 'r', encoding='utf-8') as f:
                    sandroid_data = json.load(f)
                
                # Get timeline data
                timeline_data = sandroid_data.get("Other Data", {}).get("Timeline Data", [])
                if not timeline_data:
                    return "No timeline data found in sandroid.json"
                
                # Flatten timeline data (it's a list of lists)
                all_timeline_entries = []
                for timeline_group in timeline_data:
                    if isinstance(timeline_group, list):
                        all_timeline_entries.extend(timeline_group)
                    else:
                        all_timeline_entries.append(timeline_group)
                
                # Find entries matching the specified time
                matching_entries = []
                for entry in all_timeline_entries:
                    if entry.get("seconds_after_start") == seconds_after_start:
                        matching_entries.append(entry)
                
                if not matching_entries:
                    return f"No artifacts found at {seconds_after_start} seconds after start"
                
                # Extract file paths
                file_paths = [entry.get("id", "") for entry in matching_entries if entry.get("id")]
                
                if confirmed_results_only:
                    # Get confirmed artifacts from Changed Files and New Files
                    changed_files = sandroid_data.get("Changed Files", [])
                    new_files = sandroid_data.get("New Files", [])
                    
                    # Handle the fact that changed_files might contain dictionaries for detailed changes
                    confirmed_paths = set()
                    for item in changed_files:
                        if isinstance(item, str):
                            confirmed_paths.add(item)
                        elif isinstance(item, dict):
                            confirmed_paths.update(item.keys())
                    
                    # Add new files
                    confirmed_paths.update(new_files)
                    
                    # Filter timeline results to only confirmed artifacts
                    filtered_paths = [path for path in file_paths if path in confirmed_paths]
                    
                    if not filtered_paths:
                        return f"No confirmed artifacts found at {seconds_after_start} seconds after start (found {len(file_paths)} unconfirmed files)"
                    
                    file_paths = filtered_paths
                
                # Format results
                result_lines = [f"Files at {seconds_after_start} seconds after start:"]
                for i, path in enumerate(file_paths, 1):
                    # Find the corresponding entry for additional info
                    entry = next((e for e in matching_entries if e.get("id") == path), {})
                    name = entry.get("name", os.path.basename(path))
                    result_lines.append(f"  {i}. {name}")
                    result_lines.append(f"     Path: {path}")
                
                if confirmed_results_only:
                    result_lines.append(f"\nShowing {len(file_paths)} confirmed artifacts only.")
                else:
                    result_lines.append(f"\nShowing all {len(file_paths)} files (confirmed and unconfirmed).")
                
                return "\n".join(result_lines)
                
            except FileNotFoundError:
                return f"Error: sandroid.json not found at {results_path}"
            except json.JSONDecodeError as e:
                return f"Error: Invalid JSON in sandroid.json: {e}"
            except Exception as e:
                return f"Error processing timeline data: {e}"
        

        @self.task_agent.tool
        @self.chat_agent.tool
        async def web_search(ctx: RunContext[AgentDependencies], search_query: str) -> str:
            """Perform a web search. Returns short excerpts from top results. Can for example be used to look up specific files or databases."""
            brave_key = os.getenv("BRAVE_SEARCH_API_KEY")
            if brave_key is None:
                ctx.deps.log_progress(f" ⚙️ Agent attempted to use tool: Search web for {search_query}. Set BRAVE_SEARCH_API_KEY environment variable to enable.")
                return "Web search is currently unavailable because the user has not specified an API key yet."
            ctx.deps.log_progress(f" ⚙️  Agent using tool: Search web for {search_query}")
            try:
                response = requests.get(
                    "https://api.search.brave.com/res/v1/web/search",
                    headers={
                        "Accept": "application/json",
                        "Accept-Encoding": "gzip",
                        "x-subscription-token": brave_key
                    },
                    params={
                        "q": search_query,
                        "size": 5
                    },
                ).json()
                web_results = response.get("web", {}).get("results", [])
                if not web_results:
                    return f"No web results found for query: {search_query}"
                return f"Web results for query {search_query}: {web_results}"
            except Exception as e:
                return f"Error performing web search: {e}"


        @self.task_agent.tool
        @self.chat_agent.tool
        async def submit_artifact(ctx: RunContext[AgentDependencies], artifact: str, context: str, artifact_value:int, confidence: Literal["Low", "Medium", "High"]) -> str:
            """Submit an artifact after you have reviewed it and confirmed its relevance. Submitted artifacts are saved and will be displayed to the user at the end of the task.
            Do not submit files that were created by sandroid itself as artifacts, for example UI dumps.
            Parameters:
            - artifact: Direct technical identification of the artifact, e.g file path, file path plus variable name, ip address, process name, etc.
            - context: Short explanation of the artifact. No longer than a sentence.
            - artifact_value: Integer from 1-1000 inclusive indicating how valuable the artifact is. Higher is more valuable. A value of 1000 means all criteria for a valuable artifact are fully and strongly met.
            - confidence: Your confidence in your overall assessment and that you made no errors regarding this artifact. Lower the value if you are unsure of any aspect. Use only the string literals "Low", "Medium", or "High".
            """
            ctx.deps.log_progress(f" ⚙️  Agent using tool: Submit artifact {artifact}. Artifact valued at {artifact_value} and confidence {confidence}")

            if artifact_value < 1:
                artifact_value = 1
            if artifact_value > 1000:
                artifact_value = 1000

            new_artifact = {
                "artifact": artifact,
                "context": context,
                "artifact_value": artifact_value,
                "confidence": confidence
            }
            
            self.artifacts.append(new_artifact)

            return f"Artifact submitted successfully: {new_artifact}"

        # PLACEHOLDER: Add more tools here
        # @self.task_agent.tool
        # @self.chat_agent.tool
        # async def your_custom_tool(ctx: RunContext[AgentDependencies], param: str) -> str:
        #     """Description of what your tool does."""
        #     # Your tool implementation
        #     return "Tool result"

    async def find_artifacts(self, task: str, context: Dict[str, Any] = None) -> TaskResult:
        """Correlate the ground truth and sandroid output. With progress updates"""
        if context is None:
            context = {}

        deps = AgentDependencies(
            config=self.config,
            task_context=context,
            progress_callback=self._progress_callback
        )

        try:
            logger.info("Analyzing Sandroid results with AI")

            result = await self.task_agent.run(task, deps=deps)

            self.task_result = result.output
            self.conversation_history = result.new_messages()
            self.initial_task_completed = True

            logger.info("Results analyzed successfully")
            # logger.info(f"Steps taken: {len(self.task_result.steps_taken)}")

            # Display the result
            result_string = self.task_result.result
            print("="*40)
            print(result_string)
            print("="*40)
            print(self.artifacts)
            print("="*40)
            print(f"Tokens used: {result.usage().input_tokens}")

            return self.task_result

        except UsageLimitExceeded as e:
            print(f"❌ Usage limit exceeded: Waiting for 60 seconds, then retrying")
            raise e

        except UnexpectedModelBehavior as e:
            error_result = TaskResult(
                success=False,
                result=f"Model error: {e}",
                steps_taken=[],
                metadata={"error": "model_error"}
            )
            print(f"❌ Model error: {e}")
            return error_result

        except Exception as e:
            error_result = TaskResult(
                success=False,
                result=f"Unexpected error: {e}",
                steps_taken=[],
                metadata={"error": "unexpected_error"}
            )
            print(f"❌ Unexpected error: {e}")
            return error_result

    async def chat_loop(self):
        """Start the interactive chat mode"""
        if not self.initial_task_completed:
            print("⚠️  Sandroid results have not yet been analyzed")
            return

        print("[AI]: Do you have any questions about the results?")
        print("[AI]: Type 'quit', 'exit', or 'bye' to end the chat.")

        deps = AgentDependencies(
            config=self.config,
            task_context={"initial_result": self.task_result.model_dump()},
            progress_callback=None  # No progress updates in chat mode
        )

        while True:
            try:
                # Get user input
                user_input = input("[User]: ").strip()

                if user_input.lower() in ['quit', 'exit', 'bye', 'q']:
                    print("Conversation Ended")
                    break

                if not user_input:
                    continue

                print("[AI]: ", end="", flush=True)

                # Example assumes 'self.chat_agent' is a pydantic_ai.Agent instance

                async with self.chat_agent.run_stream(
                    user_input,
                    deps=deps,
                    message_history=self.conversation_history
                ) as result:
                    # Use stream_text with delta=True to stream only new text portions
                    async for message in result.stream_text(delta=True):
                        print(message, end="", flush=True)
                    print("\n")  # Print newline after full response

                    # Update conversation history, if needed
                    self.conversation_history.extend(result.new_messages())


            except KeyboardInterrupt:
                print("\nConversation Ended")
                break
            except Exception as e:
                print(f"Error in chat: {e}")
                continue

    def _progress_callback(self, message: str, step: Optional[int] = None):
        """Callback for progress updates"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if step is not None:
            print(f"[{timestamp}] 📍 Step {step}: {message}")
        else:
            print(f"[{timestamp}]{message}")

