import os
import json
import uuid
from datetime import datetime


# =========================================================
# PHOENIX SHIELD - CANARY TOKEN SYSTEM
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

CANARY_DIR = os.path.join(
    BASE_DIR,
    "canary"
)

CANARY_FILE = os.path.join(
    CANARY_DIR,
    "Phoenix_Shield_Confidential.txt"
)

CANARY_LOG = os.path.join(
    CANARY_DIR,
    "canary_events.json"
)

CANARY_ID = "PS-CANARY-001"


# =========================================================
# CREATE CANARY DIRECTORY
# =========================================================

def initialize_canary():

    os.makedirs(
        CANARY_DIR,
        exist_ok=True
    )

    create_canary_file()


# =========================================================
# CREATE DECOY FILE
# =========================================================

def create_canary_file():

    if os.path.exists(CANARY_FILE):
        return

    with open(
        CANARY_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "PHOENIX SHIELD\n"
            "CONFIDENTIAL PROJECT DOCUMENT\n"
            "\n"
            "Document ID: PS-CANARY-001\n"
            "\n"
            "This document is intended for "
            "authorized personnel only.\n"
        )


# =========================================================
# GET CANARY INFORMATION
# =========================================================

def get_canary_info():

    return {

        "canary_id": CANARY_ID,

        "filename":
            os.path.basename(
                CANARY_FILE
            ),

        "path":
            CANARY_FILE,

        "type":
            "CANARY_TOKEN"

    }


# =========================================================
# LOAD PREVIOUS EVENTS
# =========================================================

def load_events():

    if not os.path.exists(
        CANARY_LOG
    ):

        return []

    try:

        with open(
            CANARY_LOG,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (
        json.JSONDecodeError,
        OSError
    ):

        return []


# =========================================================
# SAVE EVENT
# =========================================================

def save_event(event):

    events = load_events()

    events.append(event)

    with open(
        CANARY_LOG,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            events,
            file,
            indent=4
        )


# =========================================================
# TRIGGER CANARY
# =========================================================

def trigger_canary(
    username="unknown",
    client_ip="unknown"
):

    event = {

        "event_id":
            str(uuid.uuid4()),

        "event":
            "CANARY_TOKEN_TRIGGERED",

        "canary_id":
            CANARY_ID,

        "canary_file":
            os.path.basename(
                CANARY_FILE
            ),

        "username":
            username,

        "client_ip":
            client_ip,

        "timestamp":
            datetime.now().isoformat(),

        "severity":
            "HIGH",

        "status":
            "ALERT"

    }

    save_event(event)

    print()
    print("=" * 65)
    print("                 PHOENIX SHIELD")
    print("=" * 65)
    print("                 CANARY ALERT")
    print("-" * 65)
    print("Unauthorized canary access detected!")
    print()
    print(
        f"Canary ID : {CANARY_ID}"
    )
    print(
        f"Username  : {username}"
    )
    print(
        f"IP Address: {client_ip}"
    )
    print(
        f"Time      : {event['timestamp']}"
    )
    print(
        f"Event ID  : {event['event_id']}"
    )
    print(
        "Severity  : HIGH"
    )
    print("=" * 65)
    print()

    return event


# =========================================================
# GET CANARY EVENTS
# =========================================================

def get_canary_events():

    return load_events()