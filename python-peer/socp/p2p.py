import asyncio, websockets, json
from .proto import new_envelope, compact_json

class PeerNode:
    def __init__(self, cfg, store):
        self.cfg = cfg
        self.store = store
        self.addr = f"ws://{cfg.bind_host}:{cfg.bind_port}"
        self.fid = f"fid:{abs(hash(self.addr)) & 0xffffffff:x}"  # placeholder until crypto
        self.neighbours = set()
        self.seen = set()

    async def serve(self):
        async def handler(ws):
            self.neighbours.add(ws)
            try:
                async for line in ws:
                    await self.on_frame(ws, line)
            finally:
                self.neighbours.discard(ws)
        return await websockets.serve(handler, self.cfg.bind_host, self.cfg.bind_port, max_size=1_000_000)

    async def dial(self, url):
        ws = await websockets.connect(url, open_timeout=5)
        self.neighbours.add(ws)
        asyncio.create_task(self.reader(ws))
        await self.send_hello(ws)

    async def reader(self, ws):
        try:
            async for line in ws:
                await self.on_frame(ws, line)
        finally:
            self.neighbours.discard(ws)

    async def on_frame(self, ws, line):
        try:
            env = json.loads(line)
        except Exception:
            return
        if env.get("msg_id") in self.seen:
            return
        self.seen.add(env.get("msg_id"))

        self.store.upsert_peer(env.get("from","unknown"), "unknown", nick=None, capabilities=None)
        self.store.add_message(env.get("msg_id"), env.get("from"), env.get("to"), env.get("type"), line)

        if env.get("type") == "CHAT":
            to = env.get("to")
            prefix = "[public]" if to and to.startswith("group:") else f"[pm {to}]"
            print(f"{prefix} {env.get('from')}: {env.get('body',{}).get('text','')}")

        ttl = int(env.get("ttl", 0)) - 1
        if ttl <= 0:
            return
        env["ttl"] = ttl
        out = compact_json(env)
        for n in list(self.neighbours):
            if n is ws:
                continue
            try:
                await n.send(out)
            except Exception:
                self.neighbours.discard(n)

    async def send_hello(self, ws):
        env = new_envelope(typ="HELLO", to="group:public", frm=self.fid, ttl=2, body={"nick": self.cfg.nick, "addr": self.addr})
        await ws.send(compact_json(env))

    async def say_public(self, text):
        env = new_envelope(typ="CHAT", to="group:public", frm=self.fid, ttl=6, body={"text": text})
        frame = compact_json(env)
        for n in list(self.neighbours):
            try:
                await n.send(frame)
            except Exception:
                self.neighbours.discard(n)
