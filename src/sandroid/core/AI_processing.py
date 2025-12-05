import json
import os
import re
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from logging import WARNING, getLogger
from typing import Dict, List, Optional, Tuple

# Optional dependency - make Google GenAI optional
try:
    from google import genai

    GENAI_AVAILABLE = True
except ImportError:
    genai = None
    GENAI_AVAILABLE = False

from .adb import Adb
from .toolbox import Toolbox

logger = getLogger(__name__)


@contextmanager
def _raise_log_level_temporarily(level: int = WARNING):
    """Temporarily raise the root logger level to reduce external noise."""

    root_logger = getLogger()
    previous_level = root_logger.level
    root_logger.setLevel(level)

    handler_levels = []
    for handler in root_logger.handlers:
        handler_levels.append((handler, handler.level))
        if handler.level == 0 or handler.level < level:
            handler.setLevel(level)

    try:
        yield
    finally:
        root_logger.setLevel(previous_level)
        for handler, prev_level in handler_levels:
            handler.setLevel(prev_level)


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

To aid you in cataloging the user actions, you are provided with a json datastructure representing a timeline of touch events. It contains the following fields:
'start_timestamp': the moment when the touch event started,
'end_timestamp': the moment when the touch event ended, anything longer than a second is likely a swipe or a long press,
'touch_x': the x coordinate of the touch input when it ended,
'touch_y': the y coordinate of the touch input when it ended,
'touch_location_description': a rough textual description of where the input ended,
'input_type': whether the input was a tap, long press or swipe,
'element': an xml representation of the UI element that was probably touched,
'element_age': how long ago before the touch input the element was last recorded, if this value is high, it might be out of date.
The true selected element may be different from the one that was recorded. The touch locations are always complete, correct and sorted, so you must represent every single data structure entry in your output in, in order.

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

class AIProcessing():

    @staticmethod
    def summarize_video(path, prompt=video_summary_prompt):
        timeline = json.dumps(AIProcessing.create_touch_timeline(), indent=2)

        client = get_genai_client()

        logger.debug(f"Uploading screen recording for AI analysis: {path}")
        with _raise_log_level_temporarily():
            video = client.files.upload(file=path)
        logger.debug(f"Uploaded file: {video.name}")

        # Wait for the file to be processed
        logger.debug("Waiting for file to be processed...")
        with _raise_log_level_temporarily():
            while video.state.name == "PROCESSING":
                time.sleep(5)
                video = client.files.get(name=video.name)

            if video.state.name == "FAILED":
                raise ValueError(f"File processing failed: {video.state}")

        logger.debug(f"File is ready: {video.state.name}")
        
        model_name = Toolbox.config.ai.video_model if Toolbox.config and Toolbox.config.ai.video_model else "gemini-2.5-flash"
        logger.info("Analyzing screen recording and inputs with AI.")
        with _raise_log_level_temporarily():
            summary = client.models.generate_content(
                model=model_name, contents=[video, video_summary_prompt+timeline]
            )
            overview = client.models.generate_content(
                model=model_name, contents=[video, video_overview_prompt]
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
        except IOError as e:
            logger.error(f"Failed to write summary to file: {e}")

        return(overview.text, summary.text)
    
    @staticmethod
    def create_touch_timeline():
        # Variables
        DEVICE_DUMMY = "/dev/input/event1"
        DEVICE_TOUCH = "/dev/input/event2"
        EVENT_TYPE_TOUCH = 3
        EVENT_CODE_FINGER_DOWN = 57
        EVENT_CODE_X_COORD = 53
        EVENT_CODE_Y_COORD = 54
        DATA_INPUT_END = 4294967295
        SWIPE_DISTANCE_THRESHOLD = 30  # pixels
        LONG_PRESS_DURATION_THRESHOLD = 800  # milliseconds


        logger.debug("Touch Timeline: Creating touch timeline from recorded inputs and UI dumps")
        # Step 1: Get screen resolution
        stdout, stderr = Adb.send_adb_command("shell wm size")
        screen_match = re.search(r'Physical size: (\d+)x(\d+)', stdout)
        if not screen_match:
            raise ValueError(f"Could not parse screen resolution from: {stdout}")
        screen_width, screen_height = int(screen_match.group(1)), int(screen_match.group(2))
        logger.debug(f"Touch Timeline: Screen resolution detected: {screen_width}x{screen_height}")
        
        # Step 2: Get touch input resolution
        stdout, stderr = Adb.send_adb_command("shell getevent -pl /dev/input/event3")
        x_match = re.search(r'ABS_MT_POSITION_X.*max (\d+)', stdout)
        y_match = re.search(r'ABS_MT_POSITION_Y.*max (\d+)', stdout)
        if not x_match or not y_match:
            raise ValueError(f"Could not parse touch input resolution from: {stdout} (stderr: {stderr})")
        touch_max_x = int(x_match.group(1))
        touch_max_y = int(y_match.group(1))
        logger.debug(f"Touch Timeline: Touch input resolution detected: {touch_max_x}x{touch_max_y}")
        
        # Step 3: Calculate scaling factors
        scale_x = screen_width / touch_max_x
        scale_y = screen_height / touch_max_y
        
        # Step 4: Read raw input events
        raw_results_path = os.getenv("RAW_RESULTS_PATH", "./")
        recording_file = os.path.join(raw_results_path, "recording.txt")
        logger.debug(f"Touch Timeline:Read raw input events from: {recording_file}")
        
        touch_events = []
        current_touch = None
        
        with open(recording_file, 'r') as f:
            lines = f.readlines()
        
        # Get the first timestamp from the recording file for relative calculations
        first_event_time = 0
        for line in lines:
            line = line.strip()
            if line:
                try:
                    first_event_time = int(line.split()[0])
                    break
                except (ValueError, IndexError):
                    continue # Skip malformed lines

        def format_timestamp_ms(ms: int) -> str:
            """Converts absolute millisecond timestamp to relative MM:SS.ss string."""
            if ms is None or not first_event_time:
                return ""
            relative_ms = ms - first_event_time
            total_seconds = relative_ms // 1000
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            hundredths = (relative_ms % 1000) // 10
            return f"{minutes:02d}:{seconds:02d}.{hundredths:02d}"

        # Step 5: Process touch events sequentially
        timeline = []
        i = 0
        last_dummy_timestamp = -1
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            
            parts = line.split()
            if len(parts) != 5:
                i += 1
                continue

            timestamp, device, event_type, event_code, data = parts
            timestamp = int(timestamp)
            event_type = int(event_type)
            event_code = int(event_code)
            data = int(data)
            
            # Ignore dummy events
            if device == DEVICE_DUMMY:
                i += 1
                continue

            # Process non-touch events
            if device is not DEVICE_TOUCH:
                # To avoid multiple entries for one key press, check timestamp
                if timestamp != last_dummy_timestamp:
                    timeline.append({
                        'start_timestamp': format_timestamp_ms(timestamp),
                        'end_timestamp': format_timestamp_ms(timestamp),
                        'touch_x': None,
                        'touch_y': None,
                        'touch_location_description': "n/a",
                        'element': "Physical button press or other non-touch input like external keyboard",
                        'element_age': 0
                    })
                    last_dummy_timestamp = timestamp
                    logger.debug(f"Touch Timeline: Processed non-touch input {i+1}")
                i += 1
                continue

            # Only process touch events with event type 3
            if event_type != EVENT_TYPE_TOUCH:
                i += 1
                continue
            
            # Touch start event
            if event_code == EVENT_CODE_FINGER_DOWN and data == 0:
                current_touch = {
                    'start_timestamp': timestamp,
                    'end_timestamp': None,
                    'raw_x': None,
                    'raw_y': None,
                    'screen_x': None,
                    'screen_y': None,
                    'input_type': None
                }
                
                # Look ahead to collect coordinates and find end event
                j = i + 1
                start_x = None
                start_x_set = False
                start_y = None
                start_y_set = False
                while j < len(lines):
                    next_line = lines[j].strip()
                    if not next_line:
                        j += 1
                        continue
                    
                    next_parts = next_line.split()
                    if len(next_parts) != 5:
                        j += 1
                        continue
                    
                    next_timestamp, next_device, next_event_type, next_event_code, next_data = next_parts
                    next_timestamp = int(next_timestamp)
                    next_event_type = int(next_event_type)
                    next_event_code = int(next_event_code)
                    next_data = int(next_data)
                    
                    if next_device != DEVICE_TOUCH or next_event_type != EVENT_TYPE_TOUCH:
                        j += 1
                        continue
                        
                    # Collect coordinates
                    if next_event_code == EVENT_CODE_X_COORD:  # X coordinate
                        if not start_x_set:
                            start_x = next_data
                            start_x_set = True
                        current_touch['raw_x'] = next_data
                    elif next_event_code == EVENT_CODE_Y_COORD:  # Y coordinate  
                        if not start_y_set:
                            start_y = next_data
                            start_y_set = True
                        current_touch['raw_y'] = next_data
                    elif next_event_code == EVENT_CODE_FINGER_DOWN and next_data == DATA_INPUT_END:  # Touch end
                        current_touch['end_timestamp'] = next_timestamp
                        break
                        
                    j += 1
                
                # Step 6: Detect swipes vs taps and create touch event entry
                if (current_touch['raw_x'] is not None and 
                    current_touch['raw_y'] is not None and
                    current_touch['end_timestamp'] is not None):
                    current_touch['screen_x'] = int(current_touch['raw_x'] * scale_x)
                    current_touch['screen_y'] = int(current_touch['raw_y'] * scale_y)
                    start_x = int(start_x * scale_x)
                    start_y = int(start_y * scale_y)

                    if (abs(current_touch['screen_x'] - start_x) > SWIPE_DISTANCE_THRESHOLD or
                        abs(current_touch['screen_y'] - start_y) > SWIPE_DISTANCE_THRESHOLD):
                        # Swipe detected
                        current_touch["input_type"] = f"This Input is a swipe from {AIProcessing.get_touch_location_description(start_x, start_y, screen_width, screen_height)} ({start_x},{start_y}) to {AIProcessing.get_touch_location_description(current_touch['screen_x'], current_touch['screen_y'], screen_width, screen_height)} ({current_touch['screen_x']},{current_touch['screen_y']})"
                    elif (current_touch['end_timestamp'] - current_touch['start_timestamp']) > LONG_PRESS_DURATION_THRESHOLD: 
                        # long press detected
                        current_touch["input_type"] = "This Input is a long press"
                    else:
                        # Tap detected
                        current_touch["input_type"] = "This Input is a normal tap"
                    touch_events.append(current_touch)
                
                current_touch = None
            
            i += 1
        
        # Step 7-8: Read and parse UI dumps
        ui_dumps_file = os.path.join(raw_results_path, "ui_dumps.txt")
        
        with open(ui_dumps_file, 'r') as f:
            ui_dumps_content = f.read()
        
        ui_dumps = ui_dumps_content.split('---')
        ui_dumps = [dump.strip() for dump in ui_dumps if dump.strip()]
        
        def parse_bounds(bounds_str: str) -> Tuple[int, int, int, int]:
            """Parse bounds string like '[134,172][1362,254]' into (x1, y1, x2, y2)"""
            match = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
            if match:
                return tuple(map(int, match.groups()))
            return (0, 0, 0, 0)

        def point_in_bounds(x: int, y: int, bounds: Tuple[int, int, int, int]) -> bool:
            """Check if point is within element bounds"""
            x1, y1, x2, y2 = bounds
            return x1 <= x <= x2 and y1 <= y <= y2
        
        def distance_to_element(touch_x: int, touch_y: int, bounds: Tuple[int, int, int, int]) -> float:
            """Calculate distance from touch point to closest point on element"""
            x1, y1, x2, y2 = bounds
            if point_in_bounds(touch_x, touch_y, bounds):
                return 0.0
            closest_x = max(x1, min(touch_x, x2))
            closest_y = max(y1, min(touch_y, y2))
            return ((touch_x - closest_x) ** 2 + (touch_y - closest_y) ** 2) ** 0.5
        
        def find_closest_element(root, touch_x: int, touch_y: int) -> Optional[Dict]:
            """Find most specific UI element at touch coordinates"""
            best_element = None
            smallest_area = float('inf')
            
            def traverse(node):
                nonlocal best_element, smallest_area
                
                bounds_attr = node.get('bounds')
                if bounds_attr:
                    bounds = parse_bounds(bounds_attr)
                    x1, y1, x2, y2 = bounds
                    area = (x2 - x1) * (y2 - y1)
                    
                    # Prefer smallest element containing the touch point
                    if point_in_bounds(touch_x, touch_y, bounds) and area < smallest_area:
                        smallest_area = area
                        best_element = {
                            'text': node.get('text', ''),
                            'resource_id': node.get('resource-id', ''),
                            'class': node.get('class', ''),
                            'package': node.get('package', ''),
                            'content_desc': node.get('content-desc', ''),
                            'bounds': bounds_attr,
                            'clickable': node.get('clickable', 'false'),
                            'distance': 0.0
                        }
                
                for child in node:
                    traverse(child)
            
            traverse(root)
            
            # If no element contains touch point, find closest one
            if best_element is None:
                closest_element = None
                min_distance = float('inf')
                
                def find_closest(node):
                    nonlocal closest_element, min_distance
                    
                    bounds_attr = node.get('bounds')
                    if bounds_attr:
                        bounds = parse_bounds(bounds_attr)
                        distance = distance_to_element(touch_x, touch_y, bounds)
                        
                        if distance < min_distance:
                            min_distance = distance
                            closest_element = {
                                'text': node.get('text', ''),
                                'resource_id': node.get('resource-id', ''),
                                'class': node.get('class', ''),
                                'package': node.get('package', ''),
                                'content_desc': node.get('content-desc', ''),
                                'bounds': bounds_attr,
                                'clickable': node.get('clickable', 'false'),
                                'distance': distance
                            }
                    
                    for child in node:
                        find_closest(child)
                
                find_closest(root)
                best_element = closest_element
            
            return best_element
        
        # Step 9-11: Match touch events with UI elements
        
        # New Step: Parse UI dumps with their timestamps
        parsed_ui_dumps = []
        for dump_block in ui_dumps:
            try:
                timestamp_str, *xml_lines = dump_block.split('\n')
                dump_timestamp = int(timestamp_str)
                xml_content = '\n'.join(xml_lines)
                
                # Clean up potential leftover messages in the XML content
                clean_dump = xml_content.replace("UI hierchary dumped to: /dev/tty", "").strip()
                if not clean_dump:
                    continue
                
                root = ET.fromstring(clean_dump)
                parsed_ui_dumps.append({'timestamp': dump_timestamp, 'root': root})
            except (ValueError, ET.ParseError) as e:
                logger.warning(f"Could not parse a UI dump block: {e}")
                continue
        
        # Sort dumps by timestamp just in case they are out of order
        parsed_ui_dumps.sort(key=lambda d: d['timestamp'])
        
        # New Step: Match touch events to the closest preceding UI dump
        for touch_event in touch_events:
            # Find the most recent UI dump that occurred BEFORE the touch event
            best_dump = None
            for ui_dump in parsed_ui_dumps:
                if ui_dump['timestamp'] < touch_event['start_timestamp']:
                    best_dump = ui_dump
                else:
                    # Since both lists are sorted, we can stop once we pass the touch event time
                    break
            
            if best_dump:
                closest_element = find_closest_element(best_dump['root'], touch_event['screen_x'], touch_event['screen_y'])
                
                element_age_seconds = (touch_event['start_timestamp'] - best_dump['timestamp']) / 1000

                # Create unified timeline entry
                timeline_entry = {
                    'start_timestamp': format_timestamp_ms(touch_event['start_timestamp']),
                    'end_timestamp': format_timestamp_ms(touch_event['end_timestamp']),
                    'touch_x': touch_event['screen_x'],
                    'touch_y': touch_event['screen_y'],
                    'touch_location_description': AIProcessing.get_touch_location_description(
                        touch_event['screen_x'], touch_event['screen_y'], screen_width, screen_height
                    ),
                    'input_type': touch_event.get('input_type', None),
                    'element': closest_element,
                    'element_age': round(element_age_seconds, 2)
                }
                timeline.append(timeline_entry)
                logger.debug(f"Touch Timeline: Processed input {i+1}")
            else:
                logger.warning(f"No preceding UI dump found for touch event at {touch_event['start_timestamp']}")

        # Step 12: Return unified timeline, sorted by start time
        timeline.sort(key=lambda x: x['start_timestamp'])
        
        # Save timeline to a file
        timeline_file_path = os.path.join(raw_results_path, "input_timeline.json")
        try:
            with open(timeline_file_path, 'w', encoding='utf-8') as f:
                json.dump(timeline, f, indent=2)
            logger.debug(f"Input timeline saved to {timeline_file_path}")
        except IOError as e:
            logger.error(f"Failed to write input timeline to file: {e}")

        return timeline

    @staticmethod
    def get_touch_location_description(touch_x: int, touch_y: int, width: int, height: int) -> str:
                """Get a text description of the touch location on a 3x3 grid."""
                if touch_y < height / 3:
                    vertical = "top"
                elif touch_y < 2 * height / 3:
                    vertical = "middle"
                else:
                    vertical = "bottom"
                
                if touch_x < width / 3:
                    horizontal = "left"
                elif touch_x < 2 * width / 3:
                    horizontal = "center"
                else:
                    horizontal = "right"
                
                return f"{vertical} {horizontal}"


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
