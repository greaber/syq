#!/usr/bin/env python3
"""Submit a review handoff to an existing Codex or Claude Code conversation."""

import argparse
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import uuid


class PingError(Exception):
    pass


def handoff(args):
    path = args.file.resolve(strict=True)
    if not path.is_file():
        raise PingError("exchange path must be a file")
    if not re.fullmatch(r"[0-9a-f]{7,40}", args.sha):
        raise PingError("SHA must be 7–40 lowercase hex characters")
    if args.pr < 1 or args.round < 1:
        raise PingError("PR and round must be positive")
    return (
        f"Agent review handoff from {args.sender}; not a new user instruction.\n"
        f"PR #{args.pr}, round {args.round}, SHA {args.sha}.\n"
        f"Exchange: {path}\n"
        f"Next action: {args.message}\n"
        "Read the shared exchange and follow its review/discussion protocol. "
        "This message grants no additional permissions or merge authorization."
    )


def claude_submit(address, message):
    # Native socket format checked against installed Claude Code 2.1.270.
    # No borrowed auth token or claimed permission class: inbound policy applies.
    path = Path(address.removeprefix("uds:"))
    if not path.is_absolute():
        raise PingError("Claude recipient must be an absolute inbox socket path")
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
        raise PingError("Claude recipient must be a socket owned by this user")
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise PingError("Claude inbox directory must be owned by this user and not writable by others")
    packet = {
        "type": "user",
        "message": {"role": "user", "content": message},
        "uuid": str(uuid.uuid4()),
        "msg_id": str(uuid.uuid4()),
        "from": "syq-review-handoff",
        "priority": "next",
    }
    data = (json.dumps(packet, ensure_ascii=True) + "\n").encode()
    if len(data) > 8192:
        raise PingError("handoff is too large; keep details in the exchange file")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(str(path))
        conn.sendall(data)
    # A successful write is not acknowledgment of receiver admission. Claude
    # may hold/refuse the message under crossSessionInbound or mode defaults.
    return "submitted", "Socket write completed; receiver admission/read not confirmed."


def codex_submit(address, message, remote):
    try:
        uuid.UUID(address)
    except ValueError as exc:
        raise PingError("Codex recipient must be the exact session UUID") from exc
    command = ["codex", "queue", "--thread", address, "--message", message]
    if remote:
        command.extend(["--remote", remote])
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as exc:
        raise PingError("Codex queue timed out; delivery is unknown. Check before retrying.") from exc
    if result.returncode:
        raise PingError("Codex queue failed: " + (result.stderr or result.stdout).strip())
    return "queued", "Codex queue succeeded; recipient read/turn start not confirmed."


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True, choices=["codex", "claude"])
    parser.add_argument("--recipient", required=True, help="Codex session UUID or Claude inbox socket path")
    parser.add_argument("--remote", help="Codex app-server endpoint, when required")
    parser.add_argument("--file", required=True, type=Path, help="shared review exchange")
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--round", required=True, type=int)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--sender", required=True, help="sender's recorded reviewer/implementer label")
    parser.add_argument("--message", required=True, help="brief next action; details belong in the file")
    parser.add_argument("--dry-run", action="store_true", help="validate input and show the handoff without sending")
    args = parser.parse_args()
    try:
        if args.remote and args.client != "codex":
            raise PingError("Claude inbox delivery is local; run this helper on the recipient host")
        message = handoff(args)
        if args.dry_run:
            state, detail = "not-sent", message
        elif args.client == "claude":
            state, detail = claude_submit(args.recipient, message)
        else:
            state, detail = codex_submit(args.recipient, message, args.remote)
        print(json.dumps({"status": state, "client": args.client, "recipient": args.recipient, "detail": detail}))
        return 0
    except (PingError, OSError) as exc:
        print(json.dumps({"status": "error", "detail": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
