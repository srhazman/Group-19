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

## Setup & P2P Testing

### macOS/Linux
```
# go to the project root
cd /path/to/Group-19

# create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# upgrade pip and install dependencies
python3 -m pip install --upgrade pip wheel
python3 -m pip install -r python-peer/requirements.txt

# initialise database
python3 tools/init_db.py var/socp.db
```

### Windows
```
# go to project root
cd C:\path\to\Group-19

# create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# upgrade pip and install dependencies
python -m pip install --upgrade pip wheel
python -m pip install -r python-peer\requirements.txt

# initialise database
python tools\init_db.py var\socp.db
```

### Run Two Terminals

#### Terminal A (Alice)
```
# macOS/Linux
source .venv/bin/activate
PYTHONPATH=python-peer python3 -m socp.cli --bind 127.0.0.1:8047 --nick alice

# Windows PowerShell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH="python-peer"
python -m socp.cli --bind 127.0.0.1:8047 --nick alice
```

#### Terminal B (Bob)
```
# macOS/Linux
source .venv/bin/activate
PYTHONPATH=python-peer python3 -m socp.cli --bind 127.0.0.1:8051 --nick bob --bootstrap ws://127.0.0.1:8047

# Windows PowerShell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH="python-peer"
python -m socp.cli --bind 127.0.0.1:8051 --nick bob --bootstrap ws://127.0.0.1:8047
```

### Commands to Use Inside Terminal
```
# Type these commands in a peer’s terminal:

/say Hello      # sends a public message to all peers

/peers          # lists peers seen recently

/connect ws://host:port     # connect to another peer manually

/quit           # cleanly exit the peer
```

#### Example:
```
/say Hi everyone
[public] fid:98a6196: Hi everyone
/peers
 fid:98a6196   unknown    -    2025-09-03 06:47:42
```

### Inspect the Database:
```
# All peers and messages are stored in var/socp.db

sqlite3 var/socp.db '.tables'
# expect: messages  peers

sqlite3 var/socp.db 'SELECT type,from_fid,to_addr,ts FROM messages ORDER BY ts DESC LIMIT 5;'
```