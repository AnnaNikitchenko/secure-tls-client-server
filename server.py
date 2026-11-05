"""TLS-сервер з обмеженими JSON-повідомленнями, PBKDF2 та журналюванням."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import ssl
import struct
import time
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent
USERS_FILE = Path(os.environ.get("TLS_USERS_FILE", BASE / "data" / "users.json"))
LOG_FILE = Path(os.environ.get("TLS_LOG_FILE", BASE / "logs" / "server.jsonl"))
MAX_MESSAGE = 1024 * 1024
TIMEOUT = 30
MAX_FAILURES = 5
PBKDF2_ITERATIONS = 600_000
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def log_event(event: str, **fields: Any) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
    record.update(fields)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_users() -> dict[str, dict[str, Any]]:
    try:
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def verify_password(password: str, record: dict[str, Any]) -> bool:
    try:
        calculated = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(record["salt"]), int(record["iterations"]))
        return hmac.compare_digest(calculated, bytes.fromhex(record["hash"]))
    except (KeyError, ValueError, TypeError):
        return False


async def receive(reader: asyncio.StreamReader) -> dict[str, Any]:
    header = await asyncio.wait_for(reader.readexactly(4), TIMEOUT)
    size = struct.unpack("!I", header)[0]
    if not 1 <= size <= MAX_MESSAGE:
        raise ValueError("invalid_message_size")
    raw = await asyncio.wait_for(reader.readexactly(size), TIMEOUT)
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("message_must_be_object")
    return obj


async def send(writer: asyncio.StreamWriter, obj: dict[str, Any]) -> None:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_MESSAGE:
        raise ValueError("response_too_large")
    writer.write(struct.pack("!I", len(raw)) + raw)
    await asyncio.wait_for(writer.drain(), TIMEOUT)


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    ip = str(peer[0]) if peer else None
    tls = writer.get_extra_info("ssl_object")
    version = tls.version() if tls else None
    cipher_info = tls.cipher() if tls else None
    cipher = cipher_info[0] if cipher_info else None
    username = None
    failures = 0
    log_event("connection.success", ip=ip, status="success", code=200, tls_version=version, cipher=cipher)
    try:
        while True:
            try:
                msg = await receive(reader)
            except asyncio.IncompleteReadError:
                break
            except (asyncio.TimeoutError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                log_event("message.invalid", ip=ip, user=username, status="failure", code=400, tls_version=version, cipher=cipher, reason=type(exc).__name__)
                try:
                    await send(writer, {"ok": False, "error": "invalid_message"})
                except (ConnectionError, asyncio.TimeoutError):
                    break
                continue

            op = msg.get("op")
            if username is None:
                if op != "auth":
                    log_event("access.unauthorized", ip=ip, status="failure", code=401, tls_version=version, cipher=cipher, reason="authentication_required")
                    await send(writer, {"ok": False, "error": "authentication_required"})
                    continue
                name, password = msg.get("username"), msg.get("password")
                record = load_users().get(name) if isinstance(name, str) else None
                if not isinstance(password, str) or not isinstance(record, dict) or not verify_password(password, record):
                    failures += 1
                    log_event("auth.failure", ip=ip, user=name if isinstance(name, str) else None, status="failure", code=401, tls_version=version, cipher=cipher, reason="invalid_credentials")
                    await send(writer, {"ok": False, "error": "invalid_credentials", "attempts_left": max(0, MAX_FAILURES - failures)})
                    if failures >= MAX_FAILURES:
                        break
                    continue
                username = name
                log_event("auth.success", ip=ip, user=username, status="success", code=200, tls_version=version, cipher=cipher)
                await send(writer, {"ok": True, "tls_version": version, "cipher": cipher})
                continue

            if op == "quit":
                await send(writer, {"ok": True, "message": "session_closed"})
                break
            if op != "data":
                await send(writer, {"ok": False, "error": "unsupported_operation"})
                continue
            payload = msg.get("payload")
            digest = msg.get("sha256")
            if not isinstance(payload, str) or not isinstance(digest, str):
                await send(writer, {"ok": False, "error": "invalid_payload"})
                continue
            data = payload.encode("utf-8")
            actual = hashlib.sha256(data).hexdigest()
            if not hmac.compare_digest(actual, digest.lower()):
                log_event("integrity.failure", ip=ip, user=username, status="failure", code=422, tls_version=version, cipher=cipher, bytes=len(data), reason="sha256_mismatch")
                await send(writer, {"ok": False, "error": "integrity_check_failed"})
                continue
            log_event("data.success", ip=ip, user=username, status="success", code=200, tls_version=version, cipher=cipher, bytes=len(data))
            await send(writer, {"ok": True, "sha256": actual, "bytes": len(data), "message": "data_received"})
    except (ConnectionError, asyncio.TimeoutError, ssl.SSLError) as exc:
        log_event("connection.error", ip=ip, user=username, status="failure", code=500, tls_version=version, cipher=cipher, reason=type(exc).__name__)
    except Exception as exc:
        log_event("connection.error", ip=ip, user=username, status="failure", code=500, tls_version=version, cipher=cipher, reason=type(exc).__name__)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        log_event("session.closed", ip=ip, user=username, status="success", code=200, tls_version=version, cipher=cipher)


def make_server_context(cert: str, key: str) -> Any:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


async def run_server(host: str, port: int, cert: str, key: str) -> None:
    server = await asyncio.start_server(handle, host, port, ssl=make_server_context(cert, key), limit=MAX_MESSAGE + 4, ssl_handshake_timeout=TIMEOUT)
    logging.info("TLS-сервер слухає %s:%s", host, port)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Захищений TLS-сервер")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", default=str(BASE / "data" / "server.crt"))
    parser.add_argument("--key", default=str(BASE / "data" / "server.key"))
    args = parser.parse_args()
    if not Path(args.cert).is_file() or not Path(args.key).is_file():
        from generate_cert import generate
        cert_path, key_path = generate(Path(args.cert).parent)
        args.cert, args.key = str(cert_path), str(key_path)
        logging.info("Створено локальний TLS-сертифікат: %s", cert_path)
    asyncio.run(run_server(args.host, args.port, args.cert, args.key))


if __name__ == "__main__":
    main()
