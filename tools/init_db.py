#!/usr/bin/env python3
import sqlite3, os, sys, pathlib

def main(db_path="var/socp.db"):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    con = sqlite3.connect(db_path)
    sql = pathlib.Path("db/schema.sql").read_text(encoding="utf-8")
    con.executescript(sql)
    con.commit()
    con.close()
    print(f"Initialised {db_path}")

if __name__ == "__main__":
    db = sys.argv[1] if len(sys.argv) > 1 else "var/socp.db"
    main(db)
