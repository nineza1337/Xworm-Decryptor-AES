import base64
import hashlib
import ipaddress
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

SETTINGS = {
    "Hosts":       "",
    "Port":        "",
    "KEY":         "",
    "SPL":         "",
    "Sleep":       3,  # not encrypted
    "Groub":       "",
    "USBNM":       "",
    "InstallDir":  "",
    "InstallStr":  "",
    "Mutex":       "",
}

def derive_key_from_mutex(mutex_str: str, *, encoding: str = "utf-8") -> bytes:
    """
    key[0..15]  = md5[0..15]
    key[15..30] = md5[0..15]   (overlap at index 15)
    key[31]     = 0x00
    """
    md5 = hashlib.md5(mutex_str.encode(encoding)).digest()
    out = bytearray(32)
    out[0:16] = md5
    out[15:31] = md5 
    return bytes(out)

def decrypt_b64_cbc(b64_str: str, key: bytes, iv: bytes) -> bytes:
    ct = base64.b64decode(b64_str)
    pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
    try:
        pt = unpad(pt, AES.block_size)
    except ValueError:
        pt = pt.rstrip(b"\x00")
    return pt

def to_text(b: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            s = b.decode(enc, errors="ignore").strip("\x00")
            if s:
                return s
        except Exception:
            pass
    return b.hex()

def main():
    mutex = SETTINGS["Mutex"]
    key = derive_key_from_mutex(mutex)
    iv  = b"\x00" * 16

    print("[Key Info]")
    print("  Mutex              :", mutex)
    print("  MD5(Mutex)         :", hashlib.md5(mutex.encode('utf-8')).hexdigest())
    print("  Derived Key (hex)  :", key.hex())
    print("  IV (hex)           :", iv.hex())
    print()

    encrypted_fields = [
        "Hosts", "Port", "KEY", "SPL", "Groub", "USBNM", "InstallDir", "InstallStr"
    ]

    results = {}
    print("=== Decrypted Settings ===")
    for name in encrypted_fields:
        raw = decrypt_b64_cbc(SETTINGS[name], key, iv)
        txt = to_text(raw)
        label = ""
        if name.lower() == "hosts":
            try:
                ipaddress.ip_address(txt)
                label = "  (IPv4)"
            except Exception:
                pass
        if name.lower() == "port" and txt.isdigit():
            label = "  (Port)"

        results[name] = txt
        print(f"{name}: {txt}{label}")
    print(f"Sleep: {SETTINGS['Sleep']}")
    
if __name__ == "__main__":
    main()
