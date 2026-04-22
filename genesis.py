import hashlib
import struct
import argparse
import time

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def get_target(nbits):
    shift = (nbits >> 24) & 0xff
    diff = nbits & 0x00ffffff
    return diff << (8 * (shift - 3))

def create_merkle_root_exact(pubkey, mensaje, ntime, nbits, recompensa):
    satoshis = int(recompensa * 100000000)
    msg_bytes = mensaje.encode('utf-8')
    
    # --- TU LÓGICA EXACTA (SIN TOCAR) ---
    part1 = b"\x04" + struct.pack("<I", nbits)
    part2 = b"\x01\x04" 
    if len(msg_bytes) < 76:
        part3 = struct.pack("<B", len(msg_bytes)) + msg_bytes
    else:
        part3 = b"\x4c" + struct.pack("<B", len(msg_bytes)) + msg_bytes
    
    script_sig = part1 + part2 + part3
    
    pk_bytes = bytes.fromhex(pubkey)
    script_pubkey = b"\x21" + pk_bytes + b"\xac" if len(pk_bytes) == 33 else b"\x41" + pk_bytes + b"\xac"

    coinbase_tx = (
        struct.pack("<I", 1) + b"\x01" + b"\x00" * 32 + 
        struct.pack("<I", 0xffffffff) + struct.pack("<B", len(script_sig)) + 
        script_sig + struct.pack("<I", 0xffffffff) + b"\x01" + 
        struct.pack("<Q", satoshis) + struct.pack("<B", len(script_pubkey)) + 
        script_pubkey + struct.pack("<I", 0)
    )
    
    return double_sha256(coinbase_tx)[::-1].hex()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', required=True) 
    parser.add_argument('-m', required=True) 
    parser.add_argument('-b', required=True) 
    parser.add_argument('-r', required=True, type=float) 
    args = parser.parse_args()

    VAR_VERSION = 1
    # Limpiamos el nBits por si el usuario mete 0x al principio
    bits_str = args.b.replace('0x', '')
    VAR_NBITS = int(bits_str, 16)
    VAR_NTIME = int(time.time())

    merkle_root = create_merkle_root_exact(args.p, args.m, VAR_NTIME, VAR_NBITS, args.r)

    print(f"Mining (Time: {VAR_NTIME})")
    target = get_target(VAR_NBITS)
    header_prefix = struct.pack("<I", VAR_VERSION) + b"\x00"*32 + bytes.fromhex(merkle_root)[::-1] + struct.pack("<I", VAR_NTIME) + struct.pack("<I", VAR_NBITS)

    for n in range(0, 0xffffffff):
        h = double_sha256(header_prefix + struct.pack("<I", n))
        if int.from_bytes(h, 'little') <= target:
            hash_final = h[::-1].hex()
            print(f"\n=== SUCCESS! RESULTS FOR CHAINPARAMS ===")
            print(f"pszTimestamp:  \"{args.m}\"")
            print(f"nTime:         {VAR_NTIME}")
            print(f"nNonce:        {n}")
            print(f"nBits:         {bits_str}")
            print(f"Merkle:        {merkle_root}")
            print(f"Hash:          {hash_final}")
            print(f"Version:          1")
            print(f"=========================================")
            break
