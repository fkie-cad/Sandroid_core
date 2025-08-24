# based on https://github.com/sukhbinder/timeline_in_python
import json
import os

import matplotlib
import matplotlib.pyplot as plt

matplotlib.use("Agg")
import random

import numpy as np


def parse_timeline(output_file):
    with open(output_file) as json_file:
        data = json.load(json_file)
        raw_timeline_data = data["Other Data"]["Timeline Data"][
            0
        ]  # TODO: Change to a merge of all Timeline data sublists
        new_files = data["New Files"]
        changed_files_raw = data["Changed Files"]
        duration = data["Action Duration"]

    changed_files_id = []
    for file in changed_files_raw:
        if isinstance(file, str):
            changed_files_id.append(file)
        if isinstance(file, dict):
            changed_files_id.append(list(file.keys())[0])

    events = []
    for tl_event in raw_timeline_data:
        # calculate average time for this id
        current_id = tl_event["id"]
        cumulative_ts = tl_event["seconds_after_start"]
        num_ts = 1
        for tl_search_event in raw_timeline_data:
            if tl_search_event["id"] == current_id:
                cumulative_ts += tl_event["seconds_after_start"]
                num_ts += 1
        average_ts = cumulative_ts / num_ts

        events_entry = (tl_event["name"], average_ts, tl_event["timeline_color"])

        id = tl_event["id"]

        # print(f"Checking if {events_entry} is NOT in {events} ({events_entry not in events}),\nand making sure that {id} in {changed_files_id} ({id in changed_files_id})\n")
        if (
            events_entry not in events and id in changed_files_id
        ):  # add changed file to timeline (color is fine)
            events.append(events_entry)

        if (
            events_entry not in events and id in new_files
        ):  # add new file to timeline (change color to green)
            events_entry = (events_entry[0], events_entry[1], "#77D077")
            if (
                events_entry not in events
            ):  # prevent double entries in timeline since events_entry was changed
                events.append(events_entry)

    events = filter_list(events)
    create_timeline(events, f"{os.getenv('RESULTS_PATH')}timeline.png", duration)


def filter_list(input_list):
    # Create a dictionary to count occurrences of each timestamp
    count_dict = {}
    for item in input_list:
        timestamp = item[1]
        if timestamp in count_dict:
            count_dict[timestamp].append(item)
        else:
            count_dict[timestamp] = [item]

    # Filter the list to ensure each timestamp occurs no more than 6 times
    filtered_list = []
    for timestamp, items in count_dict.items():
        if len(items) > 6:
            filtered_list.extend(random.sample(items, 6))
        else:
            filtered_list.extend(items)

    return filtered_list


def create_timeline(events, filename, duration):
    """Create a timeline plot with custom colors for different event types.

    :param events: A list of tuples where each tuple contains the event type, timestamp, and description.
    :param filename: The name of the PNG file to save the timeline to.
    :param duration: Duration of one of the actions
    """
    # Sort the events by timestamp
    events.sort(key=lambda x: x[1])

    # Extract the event labels, timestamps, and colors
    if len(events) != 0:
        labels, timestamps, colors = zip(*events, strict=False)

    # Create the plot
    levels = np.array([-5, 5, -3, 3, -1, 1])
    fig, ax = plt.subplots(
        figsize=((210 / 25.4) * 2.5, (297 / 25.4) * 2.5)
    )  # Adjust the figsize to make it taller

    # Create the base line
    start = 0
    stop = duration
    ax.plot((0, 0), (start, stop), "k", alpha=0.5)  # Change the base line to vertical

    # Iterate through events annotating each one
    if len(events) != 0:
        for ii, (label, timestamp, color) in enumerate(
            zip(labels, timestamps, colors, strict=False)
        ):
            level = levels[ii % 6]
            vert = "center"

            ax.scatter(
                0, timestamp, s=100, facecolor=color, edgecolor="k", zorder=9999
            )  # Change scatter to vertical
            # Plot a line up to the text
            ax.plot(
                (0, level), (timestamp, timestamp), c=color, alpha=0.7
            )  # Change line to vertical
            # Give the text a faint background and align it properly
            if len(label) > 17:
                label = label[0:17] + "..."
            ax.text(
                level,
                timestamp,
                label,
                ha="center",
                va=vert,
                fontsize=18,
                backgroundcolor=(1.0, 1.0, 1.0),
                color=color,
            )  # Change text to vertical

    # Set the yticks formatting
    ax.get_yaxis().set_major_locator(plt.MaxNLocator(integer=True))
    ax.set_ylabel("Seconds since action start")

    fig.autofmt_xdate()  # Use autofmt_xdate() instead

    # Remove components for a cleaner look
    plt.setp(
        (ax.get_xticklabels() + ax.get_xticklines() + list(ax.spines.values())),
        visible=False,
    )  # Change yticks to xticks

    ax.spines["left"].set_position(("axes", 0))

    plt.subplots_adjust(top=1, bottom=0, left=0.1, right=0.9, hspace=0, wspace=0)
    # Save the plot as a PNG file
    plt.savefig(filename, bbox_inches="tight", pad_inches=0)

    return ax


# Example events
events = [
    ("File Created", 1, "#C80036"),
    ("File Modified", 2, "#7ABA78"),
    ("Process Spawned", 6, "#322C2B"),
    ("Network Socket Opened", 7, "r"),
    ("File Modified", 6, "#0C1844"),
]

# Create the timeline and save it as a PNG file
# create_timeline(events, "timeline.png", 12)
if __name__ == "__main__":
    parse_timeline("sandroid.json")
