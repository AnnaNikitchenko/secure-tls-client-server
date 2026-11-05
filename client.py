"""Консольний TLS-клієнт."""
from __future__ import annotations
import argparse, asyncio, getpass, hashlib, json, ssl, struct
from pathlib import Path

MAX_MESSAGE = 1024 * 1024
TIMEOUT = 30

async def send(writer, obj):
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if not 1 <= len(raw) <= MAX_MESSAGE: raise ValueError("Повідомлення завелике.")
    writer.write(struct.pack("!I", len(raw)) + raw); await asyncio.wait_for(writer.drain(), TIMEOUT)

async def receive(reader):
    size = struct.unpack("!I", await asyncio.wait_for(reader.readexactly(4), TIMEOUT))[0]
    if not 1 <= size <= MAX_MESSAGE: raise ValueError("Некоректний розмір відповіді.")
    return json.loads((await asyncio.wait_for(reader.readexactly(size), TIMEOUT)).decode("utf-8"))

def make_client_context(ca: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx

async def run(args):
    ctx = make_client_context(args.ca)
    reader, writer = await asyncio.wait_for(asyncio.open_connection(args.host, args.port, ssl=ctx, server_hostname=args.server_name, limit=MAX_MESSAGE + 4), TIMEOUT)
    try:
        tls = writer.get_extra_info("ssl_object")
        cert = tls.getpeercert()
        print(f"TLS: {tls.version()} | cipher: {tls.cipher()[0]}")
        print("Сертифікат:", "; ".join(f"{k}={v}" for group in cert.get("subject", ()) for k, v in group))
        username = args.user or input("Логін: ")
        password = getpass.getpass("Пароль: ")
        await send(writer, {"op":"auth", "username":username, "password":password})
        response = await receive(reader)
        if not response.get("ok"):
            print("Відмовлено в автентифікації."); return
        print("Автентифікацію успішно пройдено.")
        if args.file:
            payload = Path(args.file).read_bytes().decode("utf-8")
        elif args.message is not None:
            payload = args.message
        else:
            payload = input("Текст повідомлення (або :q для виходу): ")
        if payload != ":q":
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            await send(writer, {"op":"data", "payload":payload, "sha256":digest})
            result = await receive(reader)
            if result.get("ok") and result.get("sha256") == digest:
                print(f"Дані прийнято; SHA-256 підтверджено ({result['bytes']} байт).")
            else:
                print("Сервер відхилив дані або контрольна сума не збігається.")
        await send(writer, {"op":"quit"})
        await receive(reader)
    finally:
        writer.close()
        try: await writer.wait_closed()
        except (ConnectionError, OSError): pass

def main():
    p=argparse.ArgumentParser(description="Консольний TLS-клієнт")
    p.add_argument("--host",default="127.0.0.1"); p.add_argument("--port",type=int,default=8443)
    p.add_argument("--server-name",default="localhost"); p.add_argument("--ca",default="data/server.crt")
    p.add_argument("--user"); p.add_argument("--message"); p.add_argument("--file")
    asyncio.run(run(p.parse_args()))
if __name__ == "__main__": main()
