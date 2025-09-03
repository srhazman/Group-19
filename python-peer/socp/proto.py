import time, uuid, json

def new_envelope(typ="CHAT", to="group:public", frm="fid:placeholder", ttl=6, body=None):
    return {
        "v": "0.1",
        "type": typ,
        "msg_id": uuid.uuid4().hex,
        "from": frm,
        "to": to,
        "ttl": ttl,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "body": body or {}
    }

def compact_json(obj):
    return json.dumps(obj, separators=(",",":"))
