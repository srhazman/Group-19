const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEYDIR = path.join(__dirname, '..', '..', 'var');
const KEYFILE = path.join(KEYDIR, 'node_key.pem');

function loadOrCreateKey() {
    if (!fs.existsSync(KEYDIR)) fs.mkdirSync(KEYDIR, { recursive: true });
    if (fs.existsSync(KEYFILE)) {
        const pem = fs.readFileSync(KEYFILE, 'utf8');
        return crypto.createPrivateKey(pem);
    } else {
        const { privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 4096,
            publicExponent: 0x10001,
        });
        const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
        fs.writeFileSync(KEYFILE, pem, { mode: 0o600 });
        return privateKey;
    }
}

function getPublicKeyPEM(privateKey) {
    return privateKey.export({ type: 'pkcs1', format: 'pem', public: true });
}

function getPublicKeyB64(privateKey) {
    const pubPem = getPublicKeyPEM(privateKey);
    return Buffer.from(pubPem).toString('base64');
}

function pubkeyFingerprint(privateKey) {
    const pubPem = getPublicKeyPEM(privateKey);
    const hash = crypto.createHash('sha256').update(pubPem).digest('hex');
    return 'fid:' + hash.slice(0, 16);
}

function signEnvelope(privateKey, envelope) {
    // Canonical JSON: remove 'sig' and 'ttl'
    const envCopy = Object.assign({}, envelope);
    delete envCopy.sig;
    delete envCopy.ttl;
    const canon = JSON.stringify(envCopy);
    const sig = crypto.sign('sha256', Buffer.from(canon), privateKey);
    return sig.toString('base64url');
}

function verifyEnvelopeSig(publicKeyPem, envelope) {
    if (!envelope.sig) return false;
    const envCopy = Object.assign({}, envelope);
    delete envCopy.sig;
    delete envCopy.ttl;
    const canon = JSON.stringify(envCopy);
    const pubKey = crypto.createPublicKey(publicKeyPem);
    try {
        return crypto.verify(
            'sha256',
            Buffer.from(canon),
            pubKey,
            Buffer.from(envelope.sig, 'base64url')
        );
    } catch {
        return false;
    }
}

function encryptFor(publicKeyPem, plaintext) {
    const pubKey = crypto.createPublicKey(publicKeyPem);
    return crypto.publicEncrypt(
        {
            key: pubKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        Buffer.from(plaintext)
    ).toString('base64url');
}

function decryptWith(privateKey, ciphertextB64) {
    return crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        Buffer.from(ciphertextB64, 'base64url')
    ).toString();
}

module.exports = {
    loadOrCreateKey,
    getPublicKeyPEM,
    getPublicKeyB64,
    pubkeyFingerprint,
    signEnvelope,
    verifyEnvelopeSig,
    encryptFor,
    decryptWith
};
