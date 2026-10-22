#!/usr/bin/env python3
import argparse
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit


MAX_REQUEST = 8 * 1024 * 1024
MAX_RESPONSE = 1024 * 1024
HEADER = re.compile(rb"([A-Za-z0-9-]+):([ \t]*)([^\r\n]*)")
SIGNATURE = re.compile(rb"sha256=[0-9a-fA-F]{64}\Z")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def inspect(raw, method):
    if len(raw) > MAX_REQUEST:
        raise ValueError("request exceeds 8 MiB")
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        raise ValueError("request needs CRLF header terminator")
    lines = head.split(b"\r\n")
    if not re.fullmatch(method + rb" /[^\r\n ]* HTTP/1\.1", lines[0]):
        raise ValueError("expected an HTTP/1.1 " + method.decode() + " request")
    headers = []
    for line in lines[1:]:
        match = HEADER.fullmatch(line)
        if not match:
            raise ValueError("invalid request header")
        headers.append((match.group(1).lower(), match.group(3)))
    if any(name == b"transfer-encoding" for name, _ in headers):
        raise ValueError("Transfer-Encoding is not supported")
    lengths = [value for name, value in headers if name == b"content-length"]
    if len(lengths) > 1 or (lengths and (not lengths[0].isdigit() or int(lengths[0]) != len(body))):
        raise ValueError("Content-Length does not match the body")
    if not lengths and body:
        raise ValueError("request body needs Content-Length")
    if sum(name == b"host" for name, _ in headers) != 1:
        raise ValueError("request needs one Host header")
    return lines, headers, body


def delivery(raw, new_id):
    lines, headers, body = inspect(raw, b"POST")
    ids = [value for name, value in headers if name == b"x-github-delivery"]
    signatures = [value for name, value in headers if name == b"x-hub-signature-256"]
    if len(ids) != 1 or not ids[0] or len(signatures) != 1 or not SIGNATURE.fullmatch(signatures[0]):
        raise ValueError("expected one GitHub delivery ID and SHA-256 signature")
    encoded = new_id.encode("ascii")
    if encoded == ids[0]:
        raise ValueError("new delivery ID must differ from the original")
    changed = []
    for line in lines:
        match = HEADER.fullmatch(line)
        if match and match.group(1).lower() == b"x-github-delivery":
            changed.append(match.group(1) + b":" + match.group(2) + encoded)
        else:
            changed.append(line)
    mutated = b"\r\n".join(changed) + b"\r\n\r\n" + body
    return mutated, digest(ids[0]), digest(encoded), digest(body)


def send(origin, raw, timeout, insecure):
    sock = socket.create_connection((origin.hostname, origin.port or (443 if origin.scheme == "https" else 80)), timeout)
    try:
        sock.settimeout(timeout)
        if origin.scheme == "https":
            context = ssl.create_default_context()
            if insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=origin.hostname)
            sock.settimeout(timeout)
        sock.sendall(raw)
        response = http.client.HTTPResponse(sock)
        response.begin()
        body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise ValueError("response exceeds 1 MiB")
        return response.status, body
    finally:
        sock.close()


def field(payload, path):
    value = json.loads(payload)
    for key in path.split("."):
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def state(origin, raw, path, timeout, insecure):
    status, body = send(origin, raw, timeout, insecure)
    if not 200 <= status < 300:
        raise ValueError("readback returned HTTP " + str(status))
    value = field(body, path)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    result = {"status": status, "body_sha256": digest(body), "value_sha256": digest(encoded)}
    if isinstance(value, int) and not isinstance(value, bool):
        result["value"] = value
    return result


def phase(origin, request, readback, path, timeout, insecure, wait):
    status, body = send(origin, request, timeout, insecure)
    if wait:
        time.sleep(wait)
    return {"delivery_status": status, "delivery_body_sha256": digest(body),
            "state": state(origin, readback, path, timeout, insecure)}


def main():
    parser = argparse.ArgumentParser(description="Replay a signed GitHub webhook and check receiver state")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--readback", type=Path, required=True)
    parser.add_argument("--field", required=True, help="JSON field in the readback response")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--new-id", default=str(uuid.uuid4()))
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--wait", type=float, default=0, help="seconds before each readback")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()
    origin = urlsplit(args.origin)
    if (origin.scheme not in ("http", "https") or not origin.hostname or origin.path not in ("", "/")
            or origin.query or origin.fragment or origin.username or origin.password):
        parser.error("--origin must be an HTTP origin")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,128}", args.new_id):
        parser.error("invalid delivery ID")
    if not args.field or args.timeout <= 0 or not 0 <= args.wait <= 300:
        parser.error("invalid field, timeout, or wait")
    created = False
    try:
        request = args.request.read_bytes()
        readback = args.readback.read_bytes()
        inspect(readback, b"GET")
        if readback.partition(b"\r\n\r\n")[2]:
            raise ValueError("readback must be bodyless")
        changed, old_hash, new_hash, body_hash = delivery(request, args.new_id)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            report = {"original_request_sha256": digest(request),
                      "changed_request_sha256": digest(changed),
                      "body_sha256": body_hash,
                      "original_delivery_id_sha256": old_hash,
                      "new_delivery_id_sha256": new_hash,
                      "before": state(origin, readback, args.field, args.timeout, args.insecure)}
            report["first"] = phase(origin, request, readback, args.field, args.timeout, args.insecure, args.wait)
            report["exact_replay"] = phase(origin, request, readback, args.field, args.timeout, args.insecure, args.wait)
            report["changed_id_replay"] = phase(origin, changed, readback, args.field, args.timeout, args.insecure, args.wait)
            previous = report["before"]
            for name in ("first", "exact_replay", "changed_id_replay"):
                current = report[name]["state"]
                report[name]["state_changed"] = current["value_sha256"] != previous["value_sha256"]
                if "value" in current and "value" in previous:
                    report[name]["delta"] = current["value"] - previous["value"]
                previous = current
            json.dump(report, out, indent=2)
            out.write("\n")
    except (OSError, ValueError, KeyError, IndexError, http.client.HTTPException) as error:
        if created:
            args.out.unlink(missing_ok=True)
        parser.exit(2, str(error) + "\n")
    print(args.out)


if __name__ == "__main__":
    sys.exit(main())
