# Group-19

Jonathon Sadler
Amirah Maisarah Binti Azman
Lara Grocke
Humaira Arief Azali
Kelly Wibowo

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
│       ├── cli.py                
│       ├── config.py
│       ├── p2p.py                
│       ├── proto.py              
│       ├── storage_sqlite.py     
│       └── crypto/               
└── node-peer/
    ├── package.json
    └── src/
        ├── cli.js               
        ├── p2p.js                
        └── storage.js           
```

## Public Channel Design

**Public messages are signed plaintext.**  
- All messages sent to the public channel are readable by all peers.
- Each message is signed by the sender, so recipients can verify authenticity and integrity.
- This design is chosen for discoverability, scale, and easy interoperability.
- Private messages remain encrypted with RSA.

**Why?**  
Group encryption is complex; signed plaintext meets the spec goals (integrity + authentication) reliably and is easier to interoperate with other students. It also makes the hackathon and peer review easier.

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

/all Hello      # sends a signed plaintext message to all peers

/list           # lists peers seen recently

/tell <user id> <text>   # direct message another user (encrypted)

/file <user> <path>      # send user a file (encrypted chunks)

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