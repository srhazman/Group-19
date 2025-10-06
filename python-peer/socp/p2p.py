import asyncio, websockets, json, time, logging, uuid, os, hashlib
from .proto import new_envelope, compact_json
from .crypto import (
    load_or_create_key, pubkey_fingerprint_and_b64,
    sign_pss_b64, verify_pss_b64,
    rsa_encrypt_b64, rsa_decrypt_b64, content_sig_b64
)
logger = logging.getLogger(__name__)

class PeerNode:
    def __init__(self, cfg, store):
        self.cfg = cfg
        self.store = store
        self.addr = f"ws://{cfg.bind_host}:{cfg.bind_port}"
        self.neighbours = set()
        self.seen = set()
        self.seen_ids = set()
        
        keypath = os.path.join("var", f"node_key_{self.cfg.bind_port}.pem")
        self.sk = load_or_create_key(path=keypath)  
        self.fid, self.my_pub_b64 = pubkey_fingerprint_and_b64(self.sk)
        try:
            self.store.upsert_peer(self.fid, self.addr, nick=self.cfg.nick, pubkey=self.my_pub_b64)
        except Exception:
            logger.exception("Failed to upsert local peer")
        
    def _canonical_bytes_for_sig(self, env: dict) -> bytes:
        """
        Produce canonical JSON bytes for signing/verifying.
        We remove 'sig' and 'ttl' before canonicalising so relays can change ttl.
        """
        env_copy = {k: v for k, v in env.items() if k not in ("sig", "ttl")}
        s = compact_json(env_copy)
        return s.encode()

    def _sign_env(self, env: dict) -> None:
        """Attach 'sig' to env using our private key and canonical bytes."""
        canon = self._canonical_bytes_for_sig(env)
        env["sig"] = sign_pss_b64(self.sk, canon)

    def _verify_env_sig(self, env: dict) -> bool:
        """Verify envelope signature using stored peer pubkey (if known)."""
        sender = env.get("from")
        sig = env.get("sig")
        if not sig:
            return False
        sender_pub = self.store.get_peer_pubkey(sender)
        if not sender_pub:
            return False
        canon = self._canonical_bytes_for_sig(env)
        return verify_pss_b64(sender_pub, sig, canon)

    async def serve(self):
        async def handler(ws):
            self.neighbours.add(ws)
            try:
                async for line in ws:
                    await self.on_frame(ws, line)
            finally:
                self.neighbours.discard(ws)
        
        asyncio.create_task(self.heartbeat())
        return await websockets.serve(handler, self.cfg.bind_host, self.cfg.bind_port, max_size=1_000_000)

    async def heartbeat(self):
        while True:
            await asyncio.sleep(15)
            env = new_envelope(typ="HEARTBEAT", to="group:public", frm=self.fid, ttl=2, body={})
            self._sign_env(env)
            frame = compact_json(env)
            for n in list(self.neighbours):
                try:
                    await n.send(frame)
                except Exception:
                    self.neighbours.discard(n)


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

        msg_id = env.get("msg_id")
        if not msg_id:
            msg_id = env.get("ts") 
        if not msg_id or msg_id in self.seen:
            return
        self.seen.add(msg_id)

        
        if env.get("type") == "HELLO":
            body = env.get("body", {}) or {}
            peer_fid = env.get("from")
            peer_addr = body.get("addr", "unknown")
            peer_nick = body.get("nick")
            peer_pub = body.get("pubkey")
            try:
                self.store.upsert_peer(peer_fid, peer_addr, nick=peer_nick, pubkey=peer_pub)
            except Exception:
                logger.exception("upsert_peer failed for %s", peer_fid)
            
        else:
            
            sig = env.get("sig")
            if not sig:
                logger.warning("Dropping unsigned non-HELLO from %s", env.get("from"))
                return

            sender = env.get("from")
            sender_pub = self.store.get_peer_pubkey(sender)
            if not sender_pub:
                logger.warning("No known pubkey for %s; dropping frame type=%s", sender, env.get("type"))
                return

            try:
                
                canon = compact_json({k: v for k, v in env.items() if k not in ("sig", "ttl")}).encode()
                if not verify_pss_b64(sender_pub, sig, canon):
                    logger.warning("Invalid signature from %s; dropping", sender)
                    return
            except Exception:
                logger.exception("Signature verification error for %s", sender)
                return

        
        try:
            self.store.upsert_peer(env.get("from", "unknown"), "unknown", nick=None, capabilities=None)
        except Exception:
            logger.exception("upsert_peer failed for persist")

        
        try:
            self.store.add_message(msg_id, env.get("from"), env.get("to"), env.get("type"), line)
        except Exception:
            logger.exception("add_message failed")

        
        if env.get("type") == "CHAT":
            to = env.get("to")
            body = env.get("body", {}) or {}

            
            if body.get("enc") == "RSA-OAEP-SHA256" and "cipher" in body:
                
                if to == self.fid:
                    try:
                        pt = rsa_decrypt_b64(self.sk, body["cipher"])
                        inner = json.loads(pt.decode())
                        print(f"[pm {env.get('from')}] {inner.get('text')}")
                    except Exception:
                        logger.exception("Failed to decrypt private chat from %s", env.get("from"))
            else:
                
                prefix = "[public]" if to and str(to).startswith("group:") else f"[pm {to}]"
                print(f"{prefix} {env.get('from')}: {body.get('text','')}")
        elif env.get("type") == "MSG_PUBLIC_CHANNEL":
            payload = env.get("payload", {})
            sender = env.get("from")
            ciphertext = payload.get("ciphertext")
            sender_pub = payload.get("sender_pub")
            try:
                
                pt = rsa_decrypt_b64(self.sk, ciphertext)
                print(f"[public] {sender}: {pt.decode(errors='ignore')}")
            except Exception:
                print(f"[public] {sender}: <unable to decrypt>")
        
        if env.get("type") == "FILE_START":
            payload = env.get("payload", {})
            file_id = payload.get("file_id")
            name = payload.get("name")
            size = payload.get("size")
            sha256 = payload.get("sha256")
            if env.get("to") == self.fid:
                print(f"[file] Incoming file '{name}' ({size} bytes) from {env.get('from')}")
                
                if not hasattr(self, "file_buffers"):
                    self.file_buffers = {}
                self.file_buffers[file_id] = {"chunks": {}, "name": name, "size": size, "sha256": sha256, "from": env.get("from")}
        elif env.get("type") == "FILE_CHUNK":
            payload = env.get("payload", {})
            file_id = payload.get("file_id")
            idx = payload.get("index")
            ct = payload.get("ciphertext")
            if env.get("to") == self.fid and hasattr(self, "file_buffers") and file_id in self.file_buffers:
                try:
                    chunk = rsa_decrypt_b64(self.sk, ct)
                    self.file_buffers[file_id]["chunks"][idx] = chunk
                except Exception:
                    logger.exception("Failed to decrypt file chunk")
        elif env.get("type") == "FILE_END":
            payload = env.get("payload", {})
            file_id = payload.get("file_id")
            if env.get("to") == self.fid and hasattr(self, "file_buffers") and file_id in self.file_buffers:
                buf = self.file_buffers[file_id]
                
                chunks = [buf["chunks"][i] for i in sorted(buf["chunks"])]
                data = b"".join(chunks)
            
                sha256 = hashlib.sha256(data).hexdigest()
                if sha256 != buf["sha256"]:
                    print(f"[file] Hash mismatch for '{buf['name']}' from {buf['from']}")
                else:
                    out_path = f"recv_{buf['name']}"
                    with open(out_path, "wb") as f:
                        f.write(data)
                    print(f"[file] Received file saved as {out_path}")
                del self.file_buffers[file_id]

        
        try:
            ttl = int(env.get("ttl", 0)) - 1
        except Exception:
            ttl = -1
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
        env = new_envelope(typ="HELLO", to="group:public", frm=self.fid, ttl=2,
                           body={"nick": self.cfg.nick, "addr": self.addr, "pubkey": self.my_pub_b64})
        
        self._sign_env(env)
        await ws.send(compact_json(env))

    async def say_public(self, text):
        env = new_envelope(typ="CHAT", to="group:public", frm=self.fid, ttl=6, body={"text": text})
        self._sign_env(env)
        frame = compact_json(env)
        for n in list(self.neighbours):
            try:
                await n.send(frame)
            except Exception:
                self.neighbours.discard(n)

    async def send_file(self, to_fid, path):
        import uuid, hashlib, os
        file_id = str(uuid.uuid4())
        size = os.path.getsize(path)
        name = os.path.basename(path)
        with open(path, "rb") as f:
            data = f.read()
        sha256 = hashlib.sha256(data).hexdigest()
        manifest = {
            "type": "FILE_START",
            "from": self.fid,
            "to": to_fid,
            "ts": int(time.time() * 1000),
            "payload": {
                "file_id": file_id,
                "name": name,
                "size": size,
                "sha256": sha256,
                "mode": "dm"
            }
        }
        self._sign_env(manifest)  
        frame = compact_json(manifest)
        for n in list(self.neighbours):
            try:
                await n.send(frame)
            except Exception:
                self.neighbours.discard(n)
        
        chunk_size = 512
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            ct = rsa_encrypt_b64(self.store.get_peer_pubkey(to_fid), chunk)
            chunk_msg = {
                "type": "FILE_CHUNK",
                "from": self.fid,
                "to": to_fid,
                "ts": int(time.time() * 1000),
                "payload": {
                    "file_id": file_id,
                    "index": i // chunk_size,
                    "ciphertext": ct
                }
            }
            self._sign_env(chunk_msg) 
            frame = compact_json(chunk_msg)
            for n in list(self.neighbours):
                try:
                    await n.send(frame)
                except Exception:
                    self.neighbours.discard(n)
        
        end_msg = {
            "type": "FILE_END",
            "from": self.fid,
            "to": to_fid,
            "ts": int(time.time() * 1000),
            "payload": {"file_id": file_id}
        }
        self._sign_env(end_msg) 
        frame = compact_json(end_msg)
        for n in list(self.neighbours):
            try:
                await n.send(frame)
            except Exception:
                self.neighbours.discard(n)
        for n in list(self.neighbours):
            try:
                await n.send(frame)
            except Exception:
                self.neighbours.discard(n)
    
        chunk_size = 512
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            ct = rsa_encrypt_b64(self.store.get_peer_pubkey(to_fid), chunk)
            chunk_msg = {
                "type": "FILE_CHUNK",
                "from": self.fid,
                "to": to_fid,
                "ts": int(time.time() * 1000),
                "payload": {
                    "file_id": file_id,
                    "index": i // chunk_size,
                    "ciphertext": ct
                }
            }
            self._sign_env(chunk_msg)  
            frame = compact_json(chunk_msg)
            for n in list(self.neighbours):
                try:
                    await n.send(frame)
                except Exception:
                    self.neighbours.discard(n)
        
        end_msg = {
            "type": "FILE_END",
            "from": self.fid,
            "to": to_fid,
            "ts": int(time.time() * 1000),
            "payload": {"file_id": file_id}
        }
        self._sign_env(end_msg)  
        frame = compact_json(end_msg)
        for n in list(self.neighbours):
            try:
                await n.send(frame)
            except Exception:
                self.neighbours.discard(n)

    async def say_private(self, to_fid, text):
        recipient_pub = self.store.get_peer_pubkey(to_fid)
        if not recipient_pub:
            raise RuntimeError("Unknown recipient pubkey for " + str(to_fid))
        
        inner = {"text": text}
        pt = compact_json(inner).encode()
        cipher_b64 = rsa_encrypt_b64(recipient_pub, pt)
        body = {"cipher": cipher_b64, "enc": "RSA-OAEP-SHA256"}
        env = new_envelope(typ="CHAT", to=to_fid, frm=self.fid, ttl=6, body=body)
        self._sign_env(env)
        frame = compact_json(env)
        for n in list(self.neighbours):
            try:
                await n.send(frame)
            except Exception:
                self.neighbours.discard(n)

