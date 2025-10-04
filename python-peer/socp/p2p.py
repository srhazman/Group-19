import asyncio, websockets, json, time, logging
from .proto import new_envelope, compact_json
from .crypto import (
    load_or_create_key, pubkey_fingerprint_and_b64,
    sign_pss_b64, verify_pss_b64,
    rsa_encrypt_b64, rsa_decrypt_b64
)
logger = logging.getLogger(__name__)

class PeerNode:
    def __init__(self, cfg, store):
        self.cfg = cfg
        self.store = store
        self.addr = f"ws://{cfg.bind_host}:{cfg.bind_port}"
        self.neighbours = set()
        self.seen = set()
        # crypto: load/create RSA key and stable fid + base64 pubkey
        self.sk = load_or_create_key() # cryptography private key object
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

        # require msg_id
        msg_id = env.get("msg_id")
        if not msg_id:
            return

        # replay suppression
        if msg_id in self.seen:
            return
        self.seen.add(msg_id)

        # HELLO handling: accept and store peer pubkey (HELLO carries pubkey)
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
            # accept HELLO even if sig can't be verified (HELLO supplies pubkey)
        else:
            # Non-HELLO: require signature and known pubkey
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
                # canonical JSON excludes sig and ttl for verification
                canon = compact_json({k: v for k, v in env.items() if k not in ("sig", "ttl")}).encode()
                if not verify_pss_b64(sender_pub, sig, canon):
                    logger.warning("Invalid signature from %s; dropping", sender)
                    return
            except Exception:
                logger.exception("Signature verification error for %s", sender)
                return

        # bookkeeping: ensure peer row exists
        try:
            self.store.upsert_peer(env.get("from", "unknown"), "unknown", nick=None, capabilities=None)
        except Exception:
            logger.exception("upsert_peer failed for persist")

        # persist raw message
        try:
            self.store.add_message(msg_id, env.get("from"), env.get("to"), env.get("type"), line)
        except Exception:
            logger.exception("add_message failed")

        # Handle CHAT messages (plaintext or encrypted)
        if env.get("type") == "CHAT":
            to = env.get("to")
            body = env.get("body", {}) or {}

            # Encrypted private chat (RSA-OAEP)
            if body.get("enc") == "RSA-OAEP-SHA256" and "cipher" in body:
                # decrypt only if it's for us
                if to == self.fid:
                    try:
                        pt = rsa_decrypt_b64(self.sk, body["cipher"])
                        inner = json.loads(pt.decode())
                        print(f"[pm {env.get('from')}] {inner.get('text')}")
                    except Exception:
                        logger.exception("Failed to decrypt private chat from %s", env.get("from"))
            else:
                # plaintext chat (public group or plaintext pm)
                prefix = "[public]" if to and str(to).startswith("group:") else f"[pm {to}]"
                print(f"{prefix} {env.get('from')}: {body.get('text','')}")

        # Forward / gossip to neighbours (decrement TTL)
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
        # sign (signature excludes ttl and sig)
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

    async def say_private(self, to_fid, text):
        recipient_pub = self.store.get_peer_pubkey(to_fid)
        if not recipient_pub:
            raise RuntimeError("Unknown recipient pubkey for " + str(to_fid))
        # inner plaintext
        inner = {"text": text}
        pt = compact_json(inner).encode()
        cipher_b64 = rsa_encrypt_b64(recipient_pub, pt)
        body = {"cipher": cipher_b64, "enc": "RSA-OAEP-SHA256"}
        env = new_envelope(typ="CHAT", to=to_fid, frm=self.fid, ttl=6, body=body)
        self._sign_env(env)
        # send to all neighbours (they route)
        frame = compact_json(env)
        for n in list(self.neighbours):
            try:
                await n.send(frame)
            except Exception:
                self.neighbours.discard(n)

