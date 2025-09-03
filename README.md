# Group-19

### File Structure Design:
```
├── README.md                     # plan, basics, decentralised workflow
├── .gitignore
├── db/
│   └── schema.sql                # peers + messages tables (SQLite)
├── tools/
│   └── init_db.py                # create var/socp.db from schema.sql
├── python-peer/
│   └── socp/
│       ├── __init__.py
│       ├── cli.py                # /connect, /say, /peers, /quit
│       ├── config.py
│       ├── p2p.py                # ws server/client, TTL flood, replay drop
│       ├── proto.py              # minimal JSON envelope (no crypto yet)
│       ├── storage_sqlite.py     # SQLite persistence
│       └── crypto/               # placeholder as of right now
└── node-peer/
    ├── package.json
    └── src/
        ├── cli.js                # same commands as Python peer
        ├── p2p.js                # ws server/client, TTL flood, replay drop
        └── storage.js            # better-sqlite3 persistence
```

