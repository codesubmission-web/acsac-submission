import socket
import os
import sys
import time
import random
import math
import pickle
import json
import base64
import hmac
import hashlib
import secrets

from sympy import randprime

#from Cryptodome.Cipher import AES
#from Cryptodome.Util import Counter


from Crypto.Cipher import AES
from Crypto.Util import Counter

# ──────────────────────────────────────────────
#  Crypto parameters (must match extprotocol32)
# ──────────────────────────────────────────────
n = 128
m = 128

tao = 2 ** 60

M = 102805560819865375360034795775555166450266292837454042697409287522006925995901

def encode(x):
    return int(round(x * tao)) % M

def decode(x):
    if x >= M // 2:
        x = x - M
    return x / tao

#p = 4023638685153034690284565268330197297  # [Version 0]
#p_inv = pow(p, -1, M)

#[Version 1 does not have p]


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

hmac_key = bytes.fromhex("f5430c07fb46d973598958c8c52f8435")

def hmac_to_mod(key: bytes, message: bytes, M: int) -> int:
    h_bytes = hmac_sha256(key, message)
    h_int = int.from_bytes(h_bytes, byteorder="big")
    return h_int % M

prg_key = bytes.fromhex(
    "1d73ecfe2e7974e690ca2193031b047e4322a1bd9effc2fd91041656a6491a95"
)

def AES_PRG(key, pid, n):
    ctr = Counter.new(
        64,
        prefix=pid,
        suffix=b'\x00' * (16 - 3 - 8)
    )
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    Arr = []
    for i in range(n):
        block = cipher.encrypt(b'\x00' * 32)
        Arr.append(int.from_bytes(block, 'big'))
    return Arr

PRF_key = bytes.fromhex(
    "a0006eddfe982ff6bf068ae8e39578e12e3da5da9c4d6d3ee9185945129566ec"
)

# ──────────────────────────────────────────────
#  Helper
# ──────────────────────────────────────────────
def recv_all(sock, n_bytes):
    data = bytearray()
    while len(data) < n_bytes:
        packet = sock.recv(n_bytes - len(data))
        if not packet:
            raise ConnectionError("socket closed")
        data.extend(packet)
    return bytes(data)

def recv_with_length(sock):
    length_bytes = recv_all(sock, 4)
    total_length = int.from_bytes(length_bytes, 'big')
    return recv_all(sock, total_length)

zero_time = time.time()

# ──────────────────────────────────────────────
#  Generate challenge PC
# ──────────────────────────────────────────────
PC = []
for i in range(n):
    b = random.randrange(0, 2)
    PC.append(1 - 2 * b)

data = pickle.dumps(PC)

# ──────────────────────────────────────────────
#  Connect to PUF, send challenge, get response
# ──────────────────────────────────────────────
client_socket_puf = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host_puf = '127.0.0.1'
port_puf = 12346

client_socket_puf.connect((host_puf, port_puf))
print(f"Connected to the PUF at {host_puf}:{port_puf}")

client_socket_puf.sendall(data)

puf_resp = client_socket_puf.recv(4096)
AC_f = pickle.loads(puf_resp)
print("Received PUF response")
print(AC_f)

# ──────────────────────────────────────────────
#  Connect to server, send challenge, get proof
# ──────────────────────────────────────────────
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '127.0.0.1'
port = 12345

client_socket.connect((host, port))
print(f"Connected to server at {host}:{port}")

client_socket.sendall(data)

# Receive {emu, sig} from server
payload_bytes = recv_with_length(client_socket)
server_payload = pickle.loads(payload_bytes)

emu = server_payload["emu"]   # list of n values mod M
sig = server_payload["sig"]   # scalar mod M

print("Received server proof (emu, sig)")

# ──────────────────────────────────────────────
#  Verification (mirrors extprotocol32 verifier)
# ──────────────────────────────────────────────

start = time.time()

# Reconstruct ALPHA using the same PRG
pid = b'PID'
ALPHA = AES_PRG(prg_key, pid, n)

# sum1 = sum_i PC[i] * r_i   (PRF randomness part)
sum1 = 0
for i in range(m):
    msg = f"PRF||PID||{i}".encode('utf-8')
    r_i = hmac_to_mod(PRF_key, msg, M)
    sum1 = sum1 + PC[i] * r_i

# Derive mu[j] from emu[j]:
#   emu[j] = sum_i PC[i] * ET[i][j]  mod M
#   ET[i][j] = p*encode(TT[i][j]) + r_ij  mod M
#   => emu[j] - sum_i PC[i]*r_ij  =  p * sum_i PC[i]*encode(TT[i][j])  mod M
#   => mu[j] = (emu[j] - sum_i PC[i]*r_ij) * p_inv  mod M
mu = []
for j in range(n):
    s = 0
    for i in range(m):
        msg = f"H||PID||{i}||{j}".encode('utf-8')
        r_ij = hmac_to_mod(hmac_key, msg, M)
        s = s + PC[i] * r_ij
    #val = ((emu[j] - s) % M) * p_inv  #[Version 0]
    val = ((emu[j] - s) % M)
    #mu.append(val % M)   #[Version 1]
    mu.append(val)

# sum2 = sum_j ALPHA[j] * mu[j]
sum2 = 0
for j in range(n):
    sum2 = sum2 + ALPHA[j] * mu[j]

# v_sig should equal sig if server is honest
v_sig = (sum1 + sum2) % M

if v_sig != sig:
    print("Linear authenticator mismatch — verification failed")
    client_socket.close()
    exit(0)

print("Linear authenticator matched")

# ──────────────────────────────────────────────
#  Derive binary response from mu and compare with PUF
# ──────────────────────────────────────────────
R_f = []
for j in range(m):
    z = decode(mu[j])   # mu[j] encodes sum_i PC[i]*TT[i][j]
    if z >= 0:
        R_f.append(1)
    else:
        R_f.append(0)

if AC_f != R_f:
    print("Server response and PUF response mismatch")
    client_socket.close()
    exit(0)

print("Verification successful")
end = time.time()
print("Client Verification time", end-start)
print("End-to-end time", end-zero_time)
client_socket.close()
