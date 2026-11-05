"""Автоматичні негативні перевірки TLS та контролю доступу."""
import asyncio, hashlib, json, socket, ssl, struct, tempfile, threading
from pathlib import Path
from generate_cert import generate
import server

async def check(host,port,ctx,name):
    return await asyncio.open_connection(host,port,ssl=ctx,server_hostname=name)

def main():
    with tempfile.TemporaryDirectory() as tmp:
        cert,key=generate(Path(tmp)); ctx=server.make_server_context(str(cert),str(key))
        server.USERS_FILE=Path(tmp)/"users.json"; server.USERS_FILE.write_text("{}",encoding="utf-8")
        server.LOG_FILE=Path(tmp)/"events.jsonl"
        loop=asyncio.new_event_loop(); ready=threading.Event(); holder={}
        def start():
            asyncio.set_event_loop(loop)
            async def boot():
                holder["srv"]=await asyncio.start_server(server.handle,"127.0.0.1",0,ssl=ctx); holder["port"]=holder["srv"].sockets[0].getsockname()[1]; ready.set()
            loop.run_until_complete(boot()); loop.run_forever()
        thread=threading.Thread(target=start,daemon=True); thread.start(); ready.wait(5); port=holder["port"]
        checks=[]
        for label,ca,name,expect_ok in [("недовірений сертифікат",None,"localhost",False),("неправильне ім'я",str(cert),"wrong.example",False)]:
            try: asyncio.run(check("127.0.0.1",port,ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context(),name)); ok=True
            except (ssl.SSLError, OSError): ok=False
            checks.append((label,ok==expect_ok))
        loop.call_soon_threadsafe(holder["srv"].close); loop.call_soon_threadsafe(loop.stop); thread.join(2); loop.close()
        failed=[name for name,passed in checks if not passed]
        print("Перевірки безпеки:")
        for name,passed in checks: print(f"{'OK' if passed else 'ПОМИЛКА'}: {name}")
        if failed: raise SystemExit("Не пройшли перевірки: "+", ".join(failed))
if __name__=="__main__": main()
