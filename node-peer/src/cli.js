const readline = require('readline');
const Store = require('./storage');
const PeerNode = require('./p2p');

async function main() {
    const store = new Store();
    await store.initSchema();

    const node = new PeerNode(store);
    await node.serve();
    console.log(`listening on ws://${node.bindHost}:${node.bindPort} as ${node.fid} (nick=${node.nick})`);

    console.log("Commands: /connect ws://host:port | /say text | /pm fid text | /sendfile fid path | /peers | /quit");

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.setPrompt('> ');
    rl.prompt();

    rl.on('line', async (line) => {
        line = line.trim();
        if (!line) return rl.prompt();
        try {
            if (line.startsWith('/connect ')) {
                const url = line.split(' ', 2)[1];
                await node.dial(url);
                console.log(`connected ${url}`);
            } else if (line.startsWith('/say ')) {
                await node.sayPublic(line.split(' ', 2)[1]); // <-- now plaintext
            } else if (line.startsWith('/pm ')) {
                const [, to_fid, ...msg] = line.split(' ');
                await node.sayPrivate(to_fid, msg.join(' '));
            } else if (line.startsWith('/sendfile ')) {
                const [, to_fid, path] = line.split(' ');
                await node.sendFile(to_fid, path);
            } else if (line === '/peers') {
                const peers = await store.recentPeers();
                for (const peer of peers) {
                    const { fid, addr, nick, last_seen } = peer;
                    console.log(`${fid.padStart(12)}  ${(addr || '-').padEnd(22)}  ${(nick || '-').padEnd(12)}  ${last_seen}`);
                }
            } else if (line === '/quit') {
                rl.close();
                await node.shutdown();
                process.exit(0);
            } else {
                console.log('unknown command');
            }
        } catch (e) {
            console.log('Error:', e.message);
        }
        rl.prompt();
    });
}

main().catch(e => { console.error(e); process.exit(1); });
