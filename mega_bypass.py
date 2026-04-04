import requests
import hashlib
import struct
import base64
import multiprocessing
import random
from Crypto.Cipher import AES

API_URL = "https://g.api.mega.co.nz/cs"


# =============================================================================
# Mega.nz Login Proof-of-Concept
# =============================================================================
# This script performs a full login to Mega.nz, bypassing their anti-bot
# protection (Hashcash solver) and extracting the Master Key + SID.
#
# Purpose: Security research and responsible disclosure.
# All cryptographic operations and bypass logic are preserved from the
# original implementation.
# =============================================================================


def bytes_to_a32(b: bytes):
    """Convert bytes to a32 (array of 32-bit unsigned integers)."""
    if len(b) % 4:
        b += b'\x00' * (4 - len(b) % 4)
    return struct.unpack(f'>{len(b)//4}I', b)


def a32_to_bytes(a):
    """Convert a32 array back to bytes."""
    return struct.pack(f'>{len(a)}I', *a)


def base64_url_decode(s: str) -> bytes:
    """Decode Mega's base64url variant."""
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)


def b64url_encode(b: bytes) -> str:
    """Encode bytes to Mega's base64url variant."""
    return base64.b64encode(b).decode().replace('+', '-').replace('/', '_').rstrip('=')


def aes_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-CBC decryption with zero IV (standard used by Mega)."""
    return AES.new(key, AES.MODE_CBC, b'\x00' * 16).decrypt(data)


# =============================================================================
# Mega Cryptography
# =============================================================================

def prepare_key(password: str):
    """Derive the key using Mega's legacy method (v1)."""
    pw = password.encode('utf-8')
    a32 = bytes_to_a32(pw + b'\x00' * (-len(pw) % 4))
    pkey = [0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56]

    for _ in range(0x10000):
        for j in range(0, len(a32), 4):
            key = [
                a32[j],
                a32[j + 1] if j + 1 < len(a32) else 0,
                a32[j + 2] if j + 2 < len(a32) else 0,
                a32[j + 3] if j + 3 < len(a32) else 0
            ]
            pkey = bytes_to_a32(
                AES.new(a32_to_bytes(pkey), AES.MODE_ECB).encrypt(a32_to_bytes(key))
            )
    return pkey


def hash_email(email: str, pkey):
    """Generate the user handle (uh) for legacy login."""
    e = email.lower().encode('utf-8')
    a32 = bytes_to_a32(e + b'\x00' * (-len(e) % 4))
    h32 = [0, 0, 0, 0]
    for i, v in enumerate(a32):
        h32[i % 4] ^= v

    aes = AES.new(a32_to_bytes(pkey), AES.MODE_ECB)
    for _ in range(0x4000):
        h32 = bytes_to_a32(aes.encrypt(a32_to_bytes(h32)))

    return b64url_encode(a32_to_bytes([h32[0], h32[2]]))


# =============================================================================
# Hashcash Solver - Anti-Bot Bypass
# =============================================================================

# These two constants are critical to Mega's anti-bot protection.
# They were chosen by Mega to make the proof-of-work intentionally expensive.

NUM_REPLICATIONS = 262144   # 2^18 - The token is replicated this many times
                            # inside a large buffer. This forces significant
                            # CPU usage, slowing down automated attacks.

TOKEN_SLOT_SIZE = 48        # Size in bytes reserved for each copy of the token
                            # in the buffer. This is an empirical value used
                            # by Mega's current implementation.

def pad_to_aes_block(data: bytes) -> bytes:
    """Pad data to a multiple of 16 bytes (AES block size)."""
    rem = len(data) % 16
    if rem != 0:
        data += b'\x00' * (16 - rem)
    return data


def calc_threshold(easiness: int) -> int:
    """Calculate the difficulty threshold for the Hashcash challenge."""
    low = easiness & 63
    mant = (low << 1) + 1
    exp = (easiness >> 6) * 7 + 3
    return (mant << exp) & 0xFFFFFFFF


def gencash(token: str, easiness: int) -> str:
    """Core function that generates a valid Hashcash solution."""
    threshold = calc_threshold(easiness)
    token_bytes = pad_to_aes_block(base64_url_decode(token))
    buffer = bytearray(4 + NUM_REPLICATIONS * TOKEN_SLOT_SIZE)

    for i in range(NUM_REPLICATIONS):
        s = 4 + i * TOKEN_SLOT_SIZE
        buffer[s:s + len(token_bytes)] = token_bytes

    while True:
        for j in range(4):
            buffer[j] = (buffer[j] + 1) & 0xFF
            if buffer[j] != 0:
                break
            if j == 3:
                return ""
        digest = hashlib.sha256(buffer).digest()
        hash_value = struct.unpack('>I', digest[:4])[0]
        if hash_value <= threshold:
            return b64url_encode(bytes(buffer[:4]))


def _worker_gencash(token, easiness, result_queue, stop_event):
    """Multiprocessing worker for Hashcash solving."""
    while not stop_event.is_set():
        result = gencash(token, easiness)
        if result:
            result_queue.put(result)
            return


def solve_hashcash(header_value: str) -> str:
    """Solve the X-Hashcash challenge using all available CPU cores."""
    parts = header_value.split(':')
    easiness = int(parts[1])
    token = parts[3]

    num_cores = max(1, multiprocessing.cpu_count())
    result_queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()

    workers = []
    for _ in range(num_cores):
        p = multiprocessing.Process(
            target=_worker_gencash,
            args=(token, easiness, result_queue, stop_event)
        )
        p.start()
        workers.append(p)

    cash_value = result_queue.get(timeout=60)
    stop_event.set()

    for p in workers:
        if p.is_alive():
            p.terminate()
            p.join()

    return cash_value


# =============================================================================
# API Layer
# =============================================================================

def make_session():
    """Create a requests session that mimics the official Mega website."""
    s = requests.Session()
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Origin': 'https://mega.nz',
        'Referer': 'https://mega.nz/',
    })
    return s


def api_request(session, data, sid=None):
    """Send request to Mega API and automatically handle Hashcash challenges."""
    params = {'id': random.randint(0, 0xFFFFFFFF)}
    if sid:
        params['sid'] = sid

    while True:
        session.headers.pop('X-Hashcash', None)
        r = session.post(API_URL, params=params, json=[data], timeout=40)

        if r.status_code == 402:   # Mega requires proof-of-work
            hc = r.headers.get('X-Hashcash') or r.headers.get('x-hashcash') or ''
            if hc:
                cash_val = solve_hashcash(hc)
                session.headers['X-Hashcash'] = f"1:{hc.split(':')[3]}:{cash_val}"
                continue

        r.raise_for_status()
        resp = r.json()
        if isinstance(resp, list):
            resp = resp[0]
        return resp


# =============================================================================
# RSA SID Decryption
# =============================================================================

def decrypt_rsa_sid(csid_b64: str, privk_b64: str, master_key):
    """Decrypt the session ID using RSA. Falls back to raw csid if decryption fails
    (common with newer accounts)."""
    try:
        privk_enc = base64_url_decode(privk_b64)
        mk_bytes = a32_to_bytes(master_key)
        privk_dec = aes_cbc_decrypt(privk_enc, mk_bytes)

        def read_mpi(data, offset):
            if offset + 1 >= len(data):
                raise IndexError("privk_dec too short")
            bits = (data[offset] << 8) | data[offset + 1]
            length = (bits + 7) // 8
            if offset + 2 + length > len(data):
                raise IndexError("privk_dec too short for MPI")
            value = int.from_bytes(data[offset + 2: offset + 2 + length], 'big')
            return value, offset + 2 + length

        p, off = read_mpi(privk_dec, 0)
        q, off = read_mpi(privk_dec, off)
        d, off = read_mpi(privk_dec, off)
        u, _ = read_mpi(privk_dec, off)

        n = p * q
        csid_bytes = base64_url_decode(csid_b64)
        m_enc = int.from_bytes(csid_bytes, 'big')
        m_dec = pow(m_enc, d, n)

        byte_len = (n.bit_length() + 7) // 8
        m_bytes = m_dec.to_bytes(byte_len, 'big')
        return b64url_encode(m_bytes[-43:])

    except Exception:
        # Fallback used by many newer accounts
        return csid_b64


# =============================================================================
# Login Function
# =============================================================================

def login(email: str, password: str):
    """Perform complete Mega.nz login and return Master Key, SID and raw response."""
    session = make_session()
    email_lower = email.lower()

    # Step 1: Get account version and salt
    pre = api_request(session, {'a': 'us0', 'user': email_lower})

    if isinstance(pre, int):
        raise Exception(f"us0 error: code {pre}")

    version = pre.get('v', 1)

    if version == 2:
        salt_bytes = base64_url_decode(pre['s'])
        for encoding in ['utf-8', 'latin-1']:
            dk = hashlib.pbkdf2_hmac('sha512', password.encode(encoding),
                                     salt_bytes, 100000, dklen=32)
            dek = dk[:16]
            uh = b64url_encode(dk[16:32])

            resp = api_request(session, {'a': 'us', 'user': email_lower, 'uh': uh})

            if isinstance(resp, dict):
                break
            if isinstance(resp, int) and resp not in (-9, -6):
                raise Exception(f"Login error: code {resp}")
        else:
            raise Exception("Incorrect email or password")
    else:
        raise Exception("v1 accounts are not supported in this version")

    # Decrypt the Master Key (the real cryptographic key of the account)
    enc_mk = base64_url_decode(resp['k'])
    master_key = bytes_to_a32(aes_cbc_decrypt(enc_mk, dek))

    csid = resp.get('csid', '')
    privk = resp.get('privk', '')
    sid = decrypt_rsa_sid(csid, privk, master_key) if csid and privk else csid

    return master_key, sid, resp


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    print("Mega.nz Login")
    print("=================\n")

    email = input("Email: ").strip()
    password = input("Password: ").strip()

    try:
        print("\nPerforming login...\n")
        master_key, sid, full_response = login(email, password)

        print("Login successful")
        print("================")
        print(f"\nSID (full):\n{sid}\n")
        print(f"Master Key (full a32 list):\n{master_key}\n")

        print("Raw response fields:")
        print(f"csid: {full_response.get('csid', 'N/A')}\n")
        print(f"privk: {full_response.get('privk', 'N/A')}\n")
        print(f"k: {full_response.get('k', 'N/A')}\n")

    except Exception as e:
        print(f"\nLogin failed: {e}")