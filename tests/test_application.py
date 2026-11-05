import asyncio, hashlib, json, ssl, struct, threading
from pathlib import Path
import pytest
import server
from add_user import add_user
from analyze_logs import analyze
from generate_cert import generate

@pytest.fixture
def running_server(tmp_path, monkeypatch):
    cert,key=generate(tmp_path/"tls")
    users=tmp_path/"users.json"; add_user("alice","correct horse battery staple",users)
    monkeypatch.setattr(server,"USERS_FILE",users); log=tmp_path/"events.jsonl"; monkeypatch.setattr(server,"LOG_FILE",log)
    loop=asyncio.new_event_loop(); state={}; ready=threading.Event()
    def worker():
        asyncio.set_event_loop(loop)
        async def start():
            state["srv"]=await asyncio.start_server(server.handle,"127.0.0.1",0,ssl=server.make_server_context(str(cert),str(key)))
            state["port"]=state["srv"].sockets[0].getsockname()[1]; ready.set()
        loop.run_until_complete(start()); loop.run_forever()
    thread=threading.Thread(target=worker,daemon=True); thread.start(); assert ready.wait(5)
    yield state["srv"],state["port"],cert,log
    async def stop():
        state["srv"].close(); await state["srv"].wait_closed()
    asyncio.run_coroutine_threadsafe(stop(),loop).result(5)
    loop.call_soon_threadsafe(loop.stop); thread.join(5); loop.close()

async def send(w,o):
    b=json.dumps(o).encode(); w.write(struct.pack("!I",len(b))+b); await w.drain()
async def recv(r):
    n=struct.unpack("!I",await r.readexactly(4))[0]; return json.loads(await r.readexactly(n))
def connect(port,ca,name="localhost"):
    return asyncio.open_connection("127.0.0.1",port,ssl=ssl.create_default_context(cafile=str(ca)),server_hostname=name)

def test_tls_auth_transfer_and_integrity(running_server):
    srv,port,cert,log=running_server
    async def scenario():
        r,w=await connect(port,cert); assert w.get_extra_info("ssl_object").version() in ("TLSv1.2","TLSv1.3")
        w.write(struct.pack("!I",1)+b"{"); await w.drain(); assert (await recv(r))["error"]=="invalid_message"
        await send(w,{"op":"auth","username":"alice","password":"correct horse battery staple"}); assert (await recv(r))["ok"]
        payload="захищене повідомлення"; digest=hashlib.sha256(payload.encode()).hexdigest()
        await send(w,{"op":"data","payload":payload,"sha256":digest}); response=await recv(r); assert response["sha256"]==digest
        await send(w,{"op":"data","payload":payload,"sha256":"0"*64}); assert (await recv(r))["error"]=="integrity_check_failed"
        await send(w,{"op":"quit"}); await recv(r); w.close(); await w.wait_closed()
    asyncio.run(scenario())
    records=[json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
    assert any(x["event"]=="auth.success" for x in records); assert any(x["event"]=="integrity.failure" for x in records)

@pytest.mark.parametrize("trusted,name,expected",[(True,"wrong.example",False),(False,"localhost",False)])
def test_certificate_rejection(running_server,trusted,name,expected):
    srv,port,cert,_=running_server
    try: asyncio.run(connect(port,cert if trusted else cert.parent/"absent.crt",name)); accepted=True
    except (ssl.SSLError,OSError): accepted=False
    assert accepted is expected

def test_auth_failures_unauthorized_limit_and_log_analysis(running_server):
    srv,port,cert,log=running_server
    async def scenario():
        r,w=await connect(port,cert); await send(w,{"op":"data","payload":"x","sha256":hashlib.sha256(b"x").hexdigest()}); assert (await recv(r))["error"]=="authentication_required"
        for i in range(5):
            user="alice" if i==0 else "nobody"
            await send(w,{"op":"auth","username":user,"password":"wrong"}); result=await recv(r)
        assert result["attempts_left"]==0
        w.close(); await w.wait_closed()
    asyncio.run(scenario())
    metrics,_=analyze(log); assert metrics["Невдалі автентифікації"]==5; assert metrics["Спроби неавторизованого доступу"]==1
