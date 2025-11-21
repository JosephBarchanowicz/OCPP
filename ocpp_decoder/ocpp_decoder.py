import json
import sys
from pprint import pprint


def decode_ocpp_frame(raw: str):
    try:
        frame = json.loads(raw)
    except json.JSONDecodeError as e:
        print("Invalid JSON:", e)
        print("Raw:", raw)
        return

    if not isinstance(frame, list) or len(frame) < 2:
        print("Invalid OCPP frame structure")
        print("Frame:", frame)
        return

    msg_type = frame[0]
    uid = frame[1]

    print("============================================")
    print(f"Raw frame: {raw}")
    print("--------------------------------------------")
    print(f"MessageTypeId: {msg_type}")
    print(f"UniqueId: {uid}")

    if msg_type == 2:
        action = frame[2]
        payload = frame[3]
        print(f"Type: CALL (charger -> CSMS)")
        print(f"Action: {action}")
        print("Payload:")
        pprint(payload)

    elif msg_type == 3:
        payload = frame[2]
        print(f"Type: CALLRESULT (response)")
        print("Payload:")
        pprint(payload)

    elif msg_type == 4:
        error_code = frame[2] if len(frame) > 2 else None
        error_desc = frame[3] if len(frame) > 3 else None
        error_details = frame[4] if len(frame) > 4 else {}
        print(f"Type: CALLERROR")
        print(f"Error Code: {error_code}")
        print(f"Error Description: {error_desc}")
        print("Error Details:")
        pprint(error_details)

    else:
        print("Unknown MessageTypeId, dumping frame:")
        pprint(frame)


if __name__ == "__main__":
    if sys.stdin.isatty():
        example = '[2,"123","BootNotification",{"Vendor":"ACME","Model":"X100"}]'
        decode_ocpp_frame(example)
    else:
        for line in sys.stdin:
            line = line.strip()
            if line:
                decode_ocpp_frame(line)
