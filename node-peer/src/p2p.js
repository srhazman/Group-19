const WebSocket = require('ws');
const crypto = require('./crypto');
const fs = require('fs');
const compactJson = crypto.compactJson;

class PeerNode {
    constructor(cfg, store) {
        this.cfg = cfg;
        this.store = store;
        this.addr = `ws://${cfg.bind_host}:${cfg.bind_port}`;
        this.neighbours = new Set();
        this.seen = new Set();
        // Load or create RSA key
        this.sk = crypto.loadOrCreateKey();
        this.pubkeyPem = crypto.getPublicKeyPEM(this.sk);
        this.pubkeyB64 = crypto.getPublicKeyB64(this.sk);
        this.fid = crypto.pubkeyFingerprint(this.sk);
        // Store self in DB
        this.store.upsertPeer(this.fid, this.addr, this.cfg.nick, this.pubkeyB64);
        // Peer pubkey cache: fid -> PEM
        this.peerPubkeys = {};
    }

    _signEnvelope(env) {
        env.sig = crypto.signEnvelope(this.sk, env);
    }

    _verifyEnvelopeSig(env) {
        const sender = env.from;
        if (!env.sig) return false;
        let pubkeyPem = this.peerPubkeys[sender];
        if (!pubkeyPem) {
            // Try to get from DB
            const pubB64 = this.store.getPeerPubkey(sender);
            if (!pubB64) return false;
            pubkeyPem = Buffer.from(pubB64, 'base64').toString();
            this.peerPubkeys[sender] = pubkeyPem;
        }
        return crypto.verifyEnvelopeSig(pubkeyPem, env);
    }

    async serve() {
        this.server = new WebSocket.Server({ host: this.cfg.bind_host, port: this.cfg.bind_port });
        this.server.on('connection', ws => this._onConnection(ws));
    }

    async dial(url) {
        const ws = new WebSocket(url);
        ws.on('open', () => {
            this.neighbours.add(ws);
            this.sendHello(ws);
        });
        ws.on('message', msg => this.onFrame(ws, msg));
    }

    async onFrame(ws, line) {
        let env;
        try { env = JSON.parse(line); } catch { return; }
        const msg_id = env.msg_id;
        if (!msg_id || this.seen.has(msg_id)) return;
        this.seen.add(msg_id);

        // HELLO handling
        if (env.type === "HELLO") {
            const body = env.body || {};
            const peer_fid = env.from;
            const peer_addr = body.addr || "unknown";
            const peer_nick = body.nick;
            const peer_pub = body.pubkey;
            if (peer_pub) {
                this.peerPubkeys[peer_fid] = Buffer.from(peer_pub, 'base64').toString();
            }
            this.store.upsertPeer(peer_fid, peer_addr, peer_nick, peer_pub);
            // Accept HELLO even if not signed
        } else {
            // Non-HELLO: require signature and known pubkey
            if (!env.sig) return;
            if (!this._verifyEnvelopeSig(env)) return;
        }

        // Bookkeeping: ensure peer row exists
        this.store.upsertPeer(env.from || "unknown", "unknown", null, null);

        // Persist raw message
        this.store.addMessage(msg_id, env.from, env.to, env.type, line);

        // Handle CHAT messages (plaintext or encrypted)
        if (env.type === "CHAT") {
            const to = env.to;
            const body = env.body || {};
            // Encrypted private chat
            if (body.enc === "RSA-OAEP-SHA256" && body.cipher) {
                if (to === this.fid) {
                    try {
                        const pt = crypto.decryptWith(this.sk, body.cipher);
                        const inner = JSON.parse(pt);
                        console.log(`[pm ${env.from}] ${inner.text}`);
                    } catch {
                        console.log(`Failed to decrypt private chat from ${env.from}`);
                    }
                }
            } else {
                // Plaintext chat
                const prefix = to && String(to).startsWith("group:") ? "[public]" : `[pm ${to}]`;
                console.log(`${prefix} ${env.from}: ${body.text || ""}`);
            }
        }

        // Forward/gossip to neighbours (decrement TTL)
        let ttl = (parseInt(env.ttl) || 0) - 1;
        if (ttl <= 0) return;
        env.ttl = ttl;
        const out = compactJson(env);
        for (const n of Array.from(this.neighbours)) {
            if (n === ws) continue;
            try { n.send(out); } catch { this.neighbours.delete(n); }
        }
    }

    async sendHello(ws) {
        const env = {
            v: "0.1",
            type: "HELLO",
            msg_id: crypto.randomUUID ? crypto.randomUUID() : require('uuid').v4(),
            from: this.fid,
            to: "group:public",
            ttl: 2,
            ts: Date.now(),                     // <- integer ms
            body: {
                nick: this.cfg.nick,
                addr: this.addr,
                pubkey: this.pubkeyB64
            }
        };
        // Sign (signature excludes ttl and sig)
        this._signEnvelope(env);
        // Send canonical JSON (sorted keys, no whitespace)
        ws.send(compactJson(env));
    }

    async sayPublic(text) {
        const env = {
            v: "0.1",
            type: "CHAT",
            msg_id: crypto.randomUUID ? crypto.randomUUID() : require('uuid').v4(),
            from: this.fid,
            to: "group:public",
            ttl: 6,
            ts: Date.now(),           // <- integer ms
            body: { text }
        };
        this._signEnvelope(env);
        const frame = compactJson(env);
        for (const n of Array.from(this.neighbours)) {
            try { n.send(frame); } catch { this.neighbours.delete(n); }
        }
    }

    async sayPrivate(to_fid, text) {
        // Get recipient pubkey
        let pubB64 = this.store.getPeerPubkey(to_fid);
        if (!pubB64) throw new Error("Unknown recipient pubkey for " + to_fid);
        const pubPem = Buffer.from(pubB64, 'base64').toString();
        // Inner plaintext
        const inner = { text };
        const pt = JSON.stringify(inner);
        const cipherB64 = crypto.encryptFor(pubPem, pt);
        const body = { cipher: cipherB64, enc: "RSA-OAEP-SHA256" };
        const env = {
            v: "0.1",
            type: "CHAT",
            msg_id: crypto.randomUUID ? crypto.randomUUID() : require('uuid').v4(),
            from: this.fid,
            to: to_fid,
            ttl: 6,
            ts: Date.now(),   // <- integer ms
            body
        };
        this._signEnvelope(env);
        const frame = compactJson(env);
        for (const n of Array.from(this.neighbours)) {
            try { n.send(frame); } catch { this.neighbours.delete(n); }
        }
    }

    async shutdown() {
        for (const ws of this.neighbours) ws.close();
        if (this.server) this.server.close();
    }
}

module.exports = PeerNode;