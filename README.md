# Group-19

Members:
- Jonathon Sadler
- Amirah Maisarah Binti Azman
- Lara Grocke
- Humaira Arief Azali
- Kelly Wibowo

Our group acknowledges that we are still uncertain if our implementation meets every requirement outlined in the task, as the rubric and brief do not clearly specify some technical and structural expectations.

Since it was mentioned that students are encouraged to test and communicate with one another, we would be happy to receive feedback, advice, or clarification on any elements we might be missing or could improve.

If you have any feedback or questions, please reach out via email:
a1802741@adelaide.edu.au


## Public Channel Design

**Public messages are signed plaintext.**  
- All messages sent to the public channel are readable by all peers.
- Each message is signed by the sender, so recipients can verify authenticity and integrity.
- Private messages remain encrypted with RSA.

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
# /all Example
/all Hi everyone
[public] fid:98a6196: Hi everyone

# /list Example
/list
fid:4a8e4c5ae2551aea: None
fid:128de964f28b509a: alice
fid:e720ffa334885c7f: bob

# /tell <user id> <text> Example
Terminal A
/tell fid:e720ffa334885c7f Hello
Terminal B
[pm fid:128de964f28b509a] hello

# /file <user> <path> Example
Terminal A
/file fid:4a8e4c5aew2551aea test.txt
Terminal B
[file] Incoming file 'test.txt' (9 bytes) from fid:0fbc228f9dbb7706
[file] Recieved file saved as recv_test.txt
```

### Inspect the Database:
```
# All peers and messages are stored in var/socp.db

sqlite3 var/socp.db '.tables'
# expect: messages  peers

sqlite3 var/socp.db 'SELECT type,from_fid,to_addr,ts FROM messages ORDER BY ts DESC LIMIT 5;'
```
