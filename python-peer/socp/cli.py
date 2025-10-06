import asyncio, sys, os
from .config import parse_args
from .storage_sqlite import Store
from .p2p import PeerNode

def main_sync():
    asyncio.run(main())

async def main():
    cfg = parse_args()
    store = Store(cfg.db_path)
    store.init_schema()

    node = PeerNode(cfg, store)
    server = await node.serve()
    print(f"listening on ws://{cfg.bind_host}:{cfg.bind_port} as {node.fid} (nick={cfg.nick})")

    
    for url in cfg.bootstrap:
        try:
            print(f"Connecting to bootstrap peer {url}...")
            await node.dial(url)
        except Exception as e:
            print(f"Bootstrap connection to {url} failed: {e}")

    print("Commands: /list | /tell <user> <text> | /all <text> | /file <user> <path> | /quit")

    while True:
        line = (await asyncio.to_thread(input)).strip()
        if not line:
            continue
        if line == "/list":
            users = store.list_users()
            for u in users:
                u_dict = dict(u)
                print(f"{u_dict['user_id']}: {u_dict.get('nick','')}")
        elif line.startswith("/tell "):
            parts = line.split(" ",2)
            if len(parts) < 3:
                print("Usage: /tell <user> <text>")
                continue
            to_fid, text = parts[1], parts[2]
            
            users = [dict(u)['user_id'] for u in store.list_users()]
            if to_fid not in users:
                print(f"User {to_fid} not found. Use /list to see users.")
                continue
            try:
                await node.say_private(to_fid, text)
            except Exception as e:
                print(f"DM failed: {e}")
        elif line.startswith("/all "):
            text = line.split(" ",1)[1]
            if not node.neighbours:
                print("No peers connected. Start another peer and connect with --bootstrap.")
                continue
            await node.say_public(text)  
        elif line.startswith("/file "):
            parts = line.split(" ",2)
            if len(parts) < 3:
                print("Usage: /file <user> <path>")
                continue
            to_fid, path = parts[1], parts[2]
            users = [dict(u)['user_id'] for u in store.list_users()]
            if to_fid not in users:
                print(f"User {to_fid} not found. Use /list to see users.")
                continue
            if not os.path.isfile(path):
                print("File not found:", path)
                continue
            try:
                await node.send_file(to_fid, path)
            except Exception as e:
                print(f"File send failed: {e}")
        elif line == "/quit":
            break
        else:
            print("unknown command")

    server.close()
    await server.wait_closed()

if __name__ == "__main__":
    try:
        main_sync()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"File send failed: {e}")
