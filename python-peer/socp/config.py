import argparse
from dataclasses import dataclass

@dataclass
class Config:
    bind_host: str = "127.0.0.1"
    bind_port: int = 8047
    nick: str = "anon"
    db_path: str = "var/socp.db"
    bootstrap: list[str] = None

def parse_args():
    ap = argparse.ArgumentParser(prog="socp")
    ap.add_argument("--bind", default="127.0.0.1:8047", help="host:port to bind")
    ap.add_argument("--nick", default="anon", help="nickname")
    ap.add_argument("--db", default="var/socp.db", help="sqlite path")
    ap.add_argument("--bootstrap", action="append", default=[], help="bootstrap ws://host:port (repeatable)")
    a = ap.parse_args()
    host, port = a.bind.split(":")
    return Config(bind_host=host, bind_port=int(port), nick=a.nick, db_path=a.db, bootstrap=a.bootstrap)
