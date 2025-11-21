import json
import argparse

DEF_LOG = "ocpp_sniffer.log"


def iter_log(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def main():
    parser = argparse.ArgumentParser(description="Analyze OCPP sniffer logs.")
    parser.add_argument("--log", default=DEF_LOG, help="Path to log file")
    parser.add_argument("--cp", help="Filter by charge point ID")
    parser.add_argument("--action", help="Filter by OCPP action (e.g. StatusNotification)")
    parser.add_argument("--only-errors", action="store_true", help="Show only CALLERROR frames")
    parser.add_argument("--connector", type=int, help="Filter by connectorId in payload")
    parser.add_argument("--idtag", help="Filter by idTag in payload")
    args = parser.parse_args()

    for rec in iter_log(args.log):
        cp_id = rec.get("charge_point_id")
        decoded = rec.get("decoded", {})
        payload = decoded.get("payload", {})
        msg_type = decoded.get("messageTypeId")
        action = decoded.get("action")

        if args.cp and cp_id != args.cp:
            continue

        # if args.only-errors and msg_type != 4:
        #     continue

        if args.action and action != args.action:
            continue

        if args.connector is not None:
            if not isinstance(payload, dict) or payload.get("connectorId") != args.connector:
                continue

        if args.idtag and isinstance(payload, dict):
            if payload.get("idTag") != args.idtag:
                continue

        ts = rec.get("timestamp")
        direction = decoded.get("direction")
        status = payload.get("status") if isinstance(payload, dict) else None
        error_code = payload.get("errorCode") if isinstance(payload, dict) else None

        print("--------------------------------------------------")
        print(f"Time: {ts}")
        print(f"CP: {cp_id}")
        print(f"Type: {msg_type}  Direction: {direction}")
        if action:
            print(f"Action: {action}")
        if status:
            print(f"Status: {status}")
        if error_code:
            print(f"ErrorCode: {error_code}")
        # if args.only-errors or msg_type == 4:
        #     print("CALLERROR details:", decoded)


if __name__ == "__main__":
    main()
