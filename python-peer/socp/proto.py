import time
import uuid
import json

def new_envelope(typ="CHAT", to="group:public", frm="fid:placeholder", ttl=6, body=None):
    """
    Create a new envelope using SOCP conventions:
    - ts is integer milliseconds since epoch
    - msg_id is a uuid hex string
    """
    return {
        "v": "0.1",
        "type": typ,
        "msg_id": uuid.uuid4().hex,
        "from": frm,
        "to": to,
        "ttl": ttl,
        "ts": int(time.time() * 1000),   
        "body": body or {}
    }

def compact_json(obj):
    """
    Canonical JSON for signing/transmission:
    - no extra whitespace (separators with no spaces)
    - stable key ordering via sort_keys=True
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)
