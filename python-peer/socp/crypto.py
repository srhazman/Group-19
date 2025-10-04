import os, base64, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asympadding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

KEYDIR = "var"
KEYFILE = os.path.join(KEYDIR, "node_key.pem")

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))

def load_or_create_key(path=KEYFILE):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        with open(path, "rb") as f:
            sk = serialization.load_pem_private_key(f.read(), password=None)
    else:
        sk = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        pem = sk.private_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PrivateFormat.PKCS8,
                               encryption_algorithm=serialization.NoEncryption())
        with open(path, "wb") as f:
            f.write(pem)
        os.chmod(path, 0o600)
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

def rsa_encrypt_b64(pub_b64: str, plaintext: bytes) -> str:
    pem = b64url_decode(pub_b64)
    pub = serialization.load_pem_public_key(pem)
    ciphertext = pub.encrypt(plaintext, asympadding.OAEP(mgf=asympadding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return b64url_encode(ciphertext)

def rsa_decrypt_b64(sk, ct_b64: str) -> bytes:
    ciphertext = b64url_decode(ct_b64)
    pt = sk.decrypt(ciphertext, asympadding.OAEP(mgf=asympadding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return pt

def sign_pss_b64(sk, data: bytes) -> str:
    sig = sk.sign(data, asympadding.PSS(mgf=asympadding.MGF1(hashes.SHA256()), salt_length=asympadding.PSS.MAX_LENGTH), hashes.SHA256())
    return b64url_encode(sig)

def verify_pss_b64(pub_b64: str, sig_b64: str, data: bytes) -> bool:
    pem = b64url_decode(pub_b64)
    pub = serialization.load_pem_public_key(pem)
    sig = b64url_decode(sig_b64)
    try:
        pub.verify(sig, data, asympadding.PSS(mgf=asympadding.MGF1(hashes.SHA256()), salt_length=asympadding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
