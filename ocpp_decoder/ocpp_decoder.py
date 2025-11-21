import asyncio
import json
from datetime import datetime, timezone

import websockets

LOG_FILE = "ocpp_sniffer.log"  # JSON lines


def decode_ocpp_frame(raw: str):
    """
    Decode a raw OCPP JSON frame into a friendly dict.
    Frame format: [MessageTypeId, UniqueId, Action?, Payload?]
    """
    try:
        frame = json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "invalid_json", "raw": raw}

    if not isinstance(frame, list) or len(frame) < 2:
        return {"error": "invalid_frame_structure", "raw": raw}

    msg_type = frame[0]
    uid = frame[1]

    if msg_type == 2:  # CALL (charger -> CSMS)
        if len(frame) != 4:
            return {"error": "invalid_call_frame", "raw": raw}
        action = frame[2]
        payload = frame[3]
        return {
            "direction": "from_cp",
            "messageTypeId": msg_type,
            "uniqueId": uid,
            "action": action,
            "payload": payload,
        }

    elif msg_type == 3:  # CALLRESULT
        if len(frame) != 3:
            return {"error": "invalid_callresult_frame", "raw": raw}
        payload = frame[2]
        return {
            "direction": "from_csms",
            "messageTypeId": msg_type,
            "uniqueId": uid,
            "payload": payload,
        }

    elif msg_type == 4:  # CALLERROR
        # [4, "uid", "errorCode", "errorDescription", {errorDetails}]
        return {
            "direction": "error",
            "messageTypeId": msg_type,
            "uniqueId": uid,
            "errorCode": frame[2] if len(frame) > 2 else None,
            "errorDescription": frame[3] if len(frame) > 3 else None,
            "errorDetails": frame[4] if len(frame) > 4 else None,
        }

    else:
        return {"error": "unknown_message_type", "raw": raw}


def log_event(cp_id: str, raw_message: str):
    """Append a structured JSON line to the log file."""
    decoded = decode_ocpp_frame(raw_message)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "charge_point_id": cp_id,
        "raw": raw_message,
        "decoded": decoded,
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


async def ws_handler(websocket, path):
    cp_id = path.strip("/") or "unknown_cp"
    print(f"[+] Charger connected: {cp_id}")

    try:
        async for message in websocket:
            # Log to file
            log_event(cp_id, message)

            decoded = decode_ocpp_frame(message)

            # Simple console summary for quick troubleshooting
            print("--------------------------------------------------")
            print(f"Time (UTC): {datetime.now(timezone.utc).isoformat()}")
            print(f"Charge Point: {cp_id}")
            if "error" in decoded and decoded["error"]:
                print("!! ERROR DECODING FRAME !!")
                print(decoded)
            else:
                print(f"Type: {decoded.get('messageTypeId')}")
                print(f"UniqueId: {decoded.get('uniqueId')}")
                action = decoded.get("action")
                if action:
                    print(f"Action: {action}")

                payload = decoded.get("payload")
                if isinstance(payload, dict):
                    # Show a few key fields commonly used for troubleshooting
                    for key in ["status", "errorCode", "connectorId", "idTag", "meterStart", "meterStop"]:
                        if key in payload:
                            print(f"{key}: {payload[key]}")

            # This sniffer doesn't reply; chargers may time out if they expect proper OCPP
            # For pure sniffing in a lab, that’s fine.
            # To behave like a real CSMS, you'd implement proper responses here.

    except websockets.ConnectionClosed:
        print(f"[-] Charger disconnected: {cp_id}")


async def main():
    async with websockets.serve(
        ws_handler,
        "0.0.0.0",
        9000,
        subprotocols=["ocpp1.6"],  # many chargers require this
    ):
        print("OCPP sniffer listening on ws://0.0.0.0:9000 (subprotocol ocpp1.6)")
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
