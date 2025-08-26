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

from .toolbox import Toolbox

logger = getLogger(__name__)


def get_genai_client():
    """Get Google GenAI client with API key from configuration or environment."""
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
    # print(summarize_video("Your friend who studied abroad.mp4"))
    # TODO: add automatic path finding

# Example output made with 2.5 flash model
"""
Here is a detailed breakdown of the provided screen recording:

*   00:00 The device's home screen is displayed. The wallpaper is a gradient from light pink at the top to a darker purple at the bottom, resembling a sunset or sunrise over mountains. At the very bottom, a Google search bar is visible with a "G" icon on the left and a microphone icon on the right. Above the search bar, a row of app icons includes: "Messages" (blue speech bubble icon) and "Chrome" (red, yellow, green, blue circular icon). Above this row, three more app icons are displayed: "Gmail" (red and white 'M' envelope icon), "Photos" (colorful pinwheel icon), and "YouTube" (red play button icon).
*   00:00 - 00:03 An upward swipe gesture is performed on the screen.
*   00:03 The app drawer is displayed. The background is a light grey. At the top, a search bar labeled "Search apps" is visible. Below it, app icons are arranged in a grid:
    *   Row 1: "Calendar" (blue icon with "20"), "Camera" (green camera icon), "Chrome" (red, yellow, green, blue circular icon), "Clock" (blue clock icon).
    *   Row 2: "Contacts" (blue person icon), "Drive" (green, yellow, blue triangle icon), "Files" (yellow folder icon), "Gmail" (red and white 'M' envelope icon).
    *   Row 3: "Google" (colorful 'G' icon), "ground_truth" (green Android robot icon), "Maps" (colorful map pin icon), "Messages" (blue speech bubble icon).
    *   Row 4: "NINA" (red radar waves icon), "Phone" (blue phone icon), "Photos" (colorful pinwheel icon), "Settings" (grey gear icon).
    *   Row 5: "TMoble" (yellow gear icon with 'T'), "YouTube" (red play button icon), "YT Music" (red play button with white music note icon).
*   00:08 The "Messages" app icon (blue speech bubble) is tapped.
*   00:09 The Messages app is launched. The screen is white, displaying a large blue circular icon with a white speech bubble in its center. This is the app's loading splash screen or an initial visual element.
*   00:10 The Messages app's empty state is displayed. The background is white. A blue outline illustration of a person with several chat bubbles around them is centered on the screen. Below the illustration, the text "Once you start a new conversation, you'll see it listed here" is visible. In the bottom-right corner, a blue floating action button (FAB) is present, labeled "Start chat" and containing a white speech bubble icon.
*   00:11 The "Start chat" FAB is tapped.
*   00:12 A new message composition screen appears. The background is white. At the top, there's a "To" label followed by an input field that reads "Type a name, phone number, or email". To the right of the input field, a grid icon (likely for accessing the full contact list) is present. Below the input field, suggested contacts or options are listed:
    *   "Create group" with a blue person icon and a plus sign.
    *   "M" (likely a section header for contacts starting with 'M').
    *   "Max Mustermann" is listed with a blue circular icon containing a white 'M'. Below the name, "1 23" is displayed, likely a phone number snippet. To the right, "Mobile" is indicated.
*   00:14 The input field "Type a name, phone number, or email" is tapped.
*   00:15 The virtual QWERTY keyboard appears from the bottom of the screen. Above the keyboard, a suggestion bar is visible, along with icons for clipboard, settings, palette, and more.
*   00:15 The contact "Max Mustermann" is tapped. A blue checkmark icon appears within the blue circle next to "Max Mustermann", indicating selection. The name "Max Mustermann" appears as a pill-shaped chip in the "To" input field at the top of the screen. The keyboard remains open.
*   00:18 The "Done" or "Enter" key (represented by a checkmark within a grey square) on the bottom right of the keyboard is tapped. This action hides the virtual keyboard and transitions the view to the chat interface for the selected contact.
*   00:19 The conversation screen with "Max Mustermann" is displayed. At the top left, the "To" field shows "Max Mustermann" as a chip. At the top right, an icon showing a person with a plus sign indicates the option to add more participants to the conversation. Below this, the text "Texting with Max Mustermann (SMS/MMS)" is displayed. Below this, an input field labeled "Text message" is visible. To its left, a plus icon (for attachments/options) and a gallery icon (for images) are present. To its right, a smiley face icon (for emojis) and a microphone icon (for voice input) are visible. The virtual QWERTY keyboard is again displayed at the bottom of the screen. The time "9:25 AM" is shown above the "Texting with..." line.
*   00:22 The user begins typing "He" into the "Text message" input field. The text "He" appears in the input field. The send button (paper airplane icon) to the right of the input field changes from grey to blue, indicating it's active. The suggestion bar above the keyboard shows "He", "Hey", and "Hello".
*   00:23 The user continues typing, and the text in the "Text message" input field now reads "Hey". The send button remains active (blue paper airplane). The suggestion bar now displays "Hey", "They", and a waving hand emoji.
*   00:25 The screen content remains identical to 00:23. The text "Hey" is in the input field, the keyboard is visible, and the send button is active.

"""
