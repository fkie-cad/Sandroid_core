import os
import time
from logging import getLogger

# Optional dependency - make Google GenAI optional
try:
    from google import genai

    GENAI_AVAILABLE = True
except ImportError:
    genai = None
    GENAI_AVAILABLE = False

logger = getLogger(__name__)


def get_genai_client():
    """Get Google GenAI client with API key from configuration or environment."""
    from .toolbox import Toolbox

    if not GENAI_AVAILABLE:
        raise ImportError(
            "Google GenAI is not available. To use AI features, install with: "
            "pip install sandroid[ai] or pip install google-genai"
        )

    # First try to get from Toolbox config (if available)
    if hasattr(Toolbox, "config") and Toolbox.config:
        api_key = (
            Toolbox.config.credentials.google_genai_api_key or Toolbox.config.ai.api_key
        )
        if api_key:
            return genai.Client(api_key=api_key)

    # Fall back to environment variable
    api_key = (
        os.getenv("SANDROID_CREDENTIALS__GOOGLE_GENAI_API_KEY")
        or os.getenv("SANDROID_AI__API_KEY")
        or os.getenv("GOOGLE_API_KEY")
    )

    if not api_key:
        raise ValueError(
            "Google GenAI API key not found. Please set it in configuration "
            "file under credentials.google_genai_api_key or use environment "
            "variable SANDROID_CREDENTIALS__GOOGLE_GENAI_API_KEY"
        )

    return genai.Client(api_key=api_key)


video_summary_prompt = """
Analyze the provided screen recording from an Android Phone.
Your task is to provide a detailed breakdown of:
- every action the user of the device takes (button presses, swipes, entering text, etc.)
- any events that occur (notifications, incoming calls, etc.)
- the content of the screen (text, images, videos, etc.)
- what app or apps are being used (whatsapp, settings, etc.). If the app is not identifiable, describe it as best as possible.

Use detailed and technical language, as if you were explaining it to a developer. Do not leave out any details, even if they seem trivial or it means repeating yourself.
Answer in form of a list of bullet points, with each point starting with the timestamp and describing a single action, event, or piece of content. Start the list off with the current app. Output only the list and nothign else.

Example 1:
- 00:00 App "WhatsApp" is open, showing a chat with "John Doe".
- 00:05 text input field at the bottom of the screen is tapped
- 00:07 - 00:11 text "Hello, how are you?" is entered into the input field
- 00:13 Send button is pressed
- 00:13 Message is sent "Hello, how are you?", appears in the chat
- 01:24 Notification from "WhatsApp" appears at the top of the screen. Content: "John Doe: I'm fine, thanks!"

Example 2:
- 00:00 Home screen is displayed, showing the time and date "12:00 PM, October 1, 2023"
- 00:02 Notification shade is pulled down
- 00:03 Left swipe on the notification shade to access quick settings
- 00:05 Wi-Fi toggle is tapped to turn off Wi-Fi
- 00:11 Home button is pressed to return to the home screen
"""
video_overview_prompt = """
Analyze the provided screen recording from an Android Phone.
Your task is to come up with one sentence summarizing the main action that occurs in the recording.

Focus on the central action (or actions if there are multiple major actions), do not go into detail, do not describe what can be seen on the screen, do not use timestamps.
DO describe the overall point of the video, what the user is doing, concicely. Use no more than 1 sentence.

Output only the overview and nothing else. Do not refer to the "user" or "device", just describe the action or event.

Example 1:
Texting with "John Doe" in WhatsApp. One message sent, one is recieved.

Example 2:
Wi-Fi turned off through quick settings.

Example 2:
ebay.com opened in chrome browser.
"""


class AIProcessing:
    @staticmethod
    def list_models():
        client = get_genai_client()
        for model in client.models.list():
            logger.info(model.name)

    @staticmethod
    def summarize_video(path, prompt=video_summary_prompt):
        from .toolbox import Toolbox

        client = get_genai_client()
        logger.info(
            "Summarizing recording, this may take a while depending on the video length"
        )
        video = client.files.upload(file=path)
        logger.debug(f"Uploaded file: {video.name}")

        # Wait for the file to be processed
        logger.debug("Waiting for file to be processed...")
        while video.state.name == "PROCESSING":
            time.sleep(5)
            video = client.files.get(name=video.name)

        if video.state.name == "FAILED":
            raise ValueError(f"File processing failed: {video.state}")

        logger.debug(f"\nFile is ready: {video.state.name}")

        logger.debug("Inferencing...")
        summary = client.models.generate_content(
            model="gemini-2.5-flash", contents=[video, video_summary_prompt]
        )
        overview = client.models.generate_content(
            model="gemini-2.5-flash", contents=[video, video_overview_prompt]
        )

        client.files.delete(name=video.name)
        logger.debug(f"Deleted file: {video.name}")

        Toolbox.submit_other_data("AI Action Summary", summary.text)
        Toolbox.submit_other_data("AI Action Overview", overview.text)
        file_path = os.getenv("RESULTS_PATH") + "action_summary.txt"
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(f"Overview: {overview.text}\n\nSummary: {summary.text}")
                logger.debug(f"Summary saved to {file_path}")
        except OSError as e:
            logger.error(f"Failed to write summary to file: {e}")

        return overview.text


if __name__ == "__main__":
    pass
