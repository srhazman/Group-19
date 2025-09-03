import asyncio, sys
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
            await node.dial(url); print(f"connected {url}")
        except Exception as e:
            print(f"bootstrap dial failed {url}: {e}")

    print("Commands: /connect ws://host:port | /say text | /peers | /quit")
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        line = (await reader.readline()).decode().strip()
        if not line:
            continue
        if line.startswith("/connect "):
            url = line.split(" ",1)[1]
            try:
                await node.dial(url); print(f"connected {url}")
            except Exception as e:
                print(f"dial failed: {e}")
        elif line.startswith("/say "):
            await node.say_public(line.split(" ",1)[1])
        elif line == "/peers":
            for fid, addr, nick, seen in store.recent_peers():
                print(f"{fid:>12}  {addr or '-':<22}  {nick or '-':<12}  {seen}")
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
