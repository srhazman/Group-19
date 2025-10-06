const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

class Storage {
    constructor(dbPath = 'var/socp.db') {
        fs.mkdirSync(path.dirname(dbPath), { recursive: true });
        this.db = new sqlite3.Database(dbPath);
        this.db.run("PRAGMA foreign_keys = ON");
    }

    async initSchema() {
        const schema = fs.readFileSync('db/schema.sql', 'utf-8');
        await new Promise((resolve, reject) =>
            this.db.exec(schema, err => err ? reject(err) : resolve())
        );
    }

    upsertPeer(fid, addr, nick = null, pubkey = null, capabilities = null) {
        const caps = capabilities ? JSON.stringify(capabilities) : null;
        this.db.run(`
            INSERT INTO peers(fid,addr,nick,pubkey,capabilities,last_seen)
            VALUES(?,?,?,?,?,CURRENT_TIMESTAMP)
            ON CONFLICT(fid) DO UPDATE SET addr=excluded.addr, nick=excluded.nick, pubkey=COALESCE(excluded.pubkey, peers.pubkey),
                capabilities=excluded.capabilities, last_seen=CURRENT_TIMESTAMP
        `, [fid, addr, nick, pubkey, caps]);
    }

    getPeerPubkey(fid) {
        const row = this.db.prepare("SELECT pubkey FROM peers WHERE fid = ?").get(fid);
        return row ? row.pubkey : null;
    }

    addMessage(msg_id, from_fid, to_addr, typ, envelope_json) {
        this.db.run(`
            INSERT INTO messages(msg_id,from_fid,to_addr,type,envelope)
            VALUES(?,?,?,?,?)
        `, [msg_id, from_fid, to_addr, typ, envelope_json], err => {
            // ignore duplicate error
        });
    }

    recentPeers(limit = 50) {
        return new Promise((resolve, reject) => {
            this.db.all(
                "SELECT fid, addr, nick, last_seen FROM peers ORDER BY last_seen DESC LIMIT ?",
                [limit],
                (err, rows) => err ? reject(err) : resolve(rows)
            );
        });
    }
}

module.exports = Storage;
