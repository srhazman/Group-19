import os, base64, hashlib, logging
logger = logging.getLogger(__name__)
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asympadding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

KEYDIR = "var"
KEYFILE = os.path.join(KEYDIR, "node_key.pem")

def b64url_encode(b: bytes):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64url_decode(s: str):
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))

def load_or_create_key(path=KEYFILE):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        with open(path, "rb") as f:
            sk = serialization.load_pem_private_key(f.read(), password=None)
    else:
        sk = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        pem = sk.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
                               encryption_algorithm=serialization.NoEncryption())
        with open(path, "wb") as f:
            f.write(pem)
        try:
            os.chmod(path, 0o600)
        except (AttributeError, PermissionError, OSError) as e:
            logger.warning("Could not set permissions on %s: %s", path, e)
    return sk

def pubkey_fingerprint_and_b64(sk):
    pub_pem = sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    h = hashlib.sha256(pub_pem).hexdigest()
    fid = f"fid:{h[:16]}"
    pub_b64 = b64url_encode(pub_pem)
    return fid, pub_b64

def rsa_encrypt_b64(pub_b64: str, plaintext: bytes):
    pem = b64url_decode(pub_b64)
    pub = serialization.load_pem_public_key(pem)
    ciphertext = pub.encrypt(plaintext, asympadding.OAEP(mgf=asympadding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return b64url_encode(ciphertext)

def rsa_decrypt_b64(sk, ct_b64: str):
    ciphertext = b64url_decode(ct_b64)
    pt = sk.decrypt(ciphertext, asympadding.OAEP(mgf=asympadding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return pt

def sign_pss_b64(sk, data: bytes) -> str:
    sig = sk.sign(data, asympadding.PSS(mgf=asympadding.MGF1(hashes.SHA256()), salt_length=asympadding.PSS.MAX_LENGTH), hashes.SHA256())
    return b64url_encode(sig)

def verify_pss_b64(pub_b64: str, sig_b64: str, data: bytes):
    try:
        pem = b64url_decode(pub_b64)
        pub = serialization.load_pem_public_key(pem)
        sig = b64url_decode(sig_b64)
        pub.verify(
            sig,
            data,
            asympadding.PSS(mgf=asympadding.MGF1(hashes.SHA256()), salt_length=asympadding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        # covers InvalidSignature and malformed inputs
        return False
    
def rsa_encrypt_chunks_b64(pub_b64: str, data: bytes):
    # key size ops: assume 4096-bit key (512 bytes)
    key_bytes = 4096 // 8
    hash_len = 32  # SHA-256
    max_plain = key_bytes - 2 * hash_len - 2
    chunks = []
    for i in range(0, len(data), max_plain):
        piece = data[i:i + max_plain]
        ct = rsa_encrypt_b64(pub_b64, piece)
        chunks.append(ct)
    return chunks

def rsa_decrypt_chunks(sk, chunks_b64):
    out = bytearray()
    for ct_b64 in chunks_b64:
        part = rsa_decrypt_b64(sk, ct_b64)
        out.extend(part)
    return bytes(out)

def content_sig_b64(sk, ciphertext_b64: str, frm: str, to: str, ts: int):
    data = (ciphertext_b64 + frm + to + str(int(ts))).encode()
    digest = hashlib.sha256(data).digest()
    return sign_pss_b64(sk, digest)

def verify_content_sig_b64(pub_b64: str, content_sig_b64: str, ciphertext_b64: str, frm: str, to: str, ts: int):
    data = (ciphertext_b64 + frm + to + str(int(ts))).encode()
    digest = hashlib.sha256(data).digest()
    return verify_pss_b64(pub_b64, content_sig_b64, digest)