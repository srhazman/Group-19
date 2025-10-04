import sqlite3, json, os

class Store:
    def __init__(self, path="var/socp.db"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.execute("PRAGMA foreign_keys = ON")

    def init_schema(self):
        # read schema relative to project root; expect to run from project root
        with open("db/schema.sql","r",encoding="utf-8") as f:
            self.con.executescript(f.read())
        self.con.commit()

    def upsert_peer(self, fid, addr, nick=None, pubkey=None, capabilities=None):
        caps = json.dumps(capabilities) if capabilities is not None else None
        self.con.execute("""
        INSERT INTO peers(fid,addr,nick,pubkey,capabilities,last_seen)
        VALUES(?,?,?,?,?,CURRENT_TIMESTAMP)
        ON CONFLICT(fid) DO UPDATE SET addr=excluded.addr, nick=excluded.nick, pubkey=COALESCE(excluded.pubkey, peers.pubkey),
            capabilities=excluded.capabilities, last_seen=CURRENT_TIMESTAMP
        """, (fid, addr, nick, pubkey, caps))
        self.con.commit()

    def get_peer_pubkey(self, fid):
        cur = self.con.execute("SELECT pubkey FROM peers WHERE fid = ?", (fid,))
        row = cur.fetchone()
        return row["pubkey"] if row else None

    def add_message(self, msg_id, from_fid, to_addr, typ, envelope_json):
        try:
            self.con.execute("""
            INSERT INTO messages(msg_id,from_fid,to_addr,type,envelope)
            VALUES(?,?,?,?,?)
            """, (msg_id, from_fid, to_addr, typ, envelope_json))
            self.con.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # duplicate (replay)

    def recent_peers(self, limit=50):
        cur = self.con.execute("SELECT fid, addr, nick, last_seen FROM peers ORDER BY last_seen DESC LIMIT ?", (limit,))
        return cur.fetchall()
