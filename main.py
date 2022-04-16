import socket, threading, os, subprocess, json, base64, time, atexit, tkinter, tkinter.scrolledtext, random, sys
import socks

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

pseed = random.randint(1, 999)
gseed = int(time.time())

def enc(data):
    return base64.b85encode(data).decode()

def dec(data):
    return base64.b85decode(data.encode())

def tor_daemon():
    os.mkdir(f"/tmp/tor{gseed}")
    os.mkdir(f"/tmp/tor{gseed}/data")

    with open(f"/tmp/tor{gseed}/torrc", "w") as f:
        f.write(f"DataDirectory /tmp/tor{gseed}data\nHiddenServiceDir {os.path.join(os.getcwd(), 'secret')}\nHiddenServiceVersion 3\nHiddenServicePort 1337 localhost:{pseed + 9000}\nSocksPort {pseed + 9001}\n")

    proc = subprocess.run(["tor", "-f", f"/tmp/tor{gseed}/torrc"], stdout=sys.stdout)
    os._exit(1)
threading.Thread(target=tor_daemon, daemon=True).start()
time.sleep(0.1)

if not os.path.isfile(os.path.join("secret", "chat_key")):
    sk = ed25519.Ed25519PrivateKey.generate()

    with open(os.path.join("secret", "chat_key"), "wb") as f:
        f.write(sk.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()))

if not os.path.isfile(os.path.join("secret", "chat_messages")):
    with open(os.path.join("secret", "chat_messages"), "w") as f:
        f.write("[]")

if not os.path.isfile(os.path.join("secret", "chat_raws")):
    with open(os.path.join("secret", "chat_raws"), "w") as f: 
        f.write("[]")

if not os.path.isfile(os.path.join("secret", "chat_config")):
    with open(os.path.join("secret", "chat_config"), "w") as f:
        f.write(json.dumps({"nodes": [], "users": {}}, indent=2))

messages = []
raws = []
config = {}
with open(os.path.join("secret", "chat_messages"), "r") as f:
    messages = json.loads(f.read())

with open(os.path.join("secret", "chat_raws"), "r") as f:
    raws = json.loads(f.read())

with open(os.path.join("secret", "chat_key"), "rb") as f:
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
    vk = sk.public_key()

username = enc(vk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
print(f"User: {username}")

with open(os.path.join("secret", "chat_config"), "r") as f:
    config = json.loads(f.read())

if not username in config["users"]:
    config["users"][username] = "Me"
    with open(os.path.join("secret", "chat_config"), "w") as f:
        f.write(json.dumps(config, indent=2))

with open(os.path.join("secret", "hostname"), "r") as f:
    host = f.read().strip()

    if not host in config["nodes"]:
        config["nodes"].append(host)
        with open(os.path.join("secret", "chat_config"), "w") as f:
            f.write(json.dumps(config, indent=2))

def client_handler(client):
    try:
        private_key = X25519PrivateKey.generate()
        client.send(private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
        peer_public_key = X25519PublicKey.from_public_bytes(client.recv(32))
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data").derive(shared_key)
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(bytes(16)))
        decryptor = cipher.decryptor()

        encraw = client.recv(2 ** 26)
        raw = decryptor.update(encraw) + decryptor.finalize()

        assert not enc(raw) in raws

        data = json.loads(raw.split(b"\x00")[0].decode())

        assert "payload" in data
        assert "sig" in data
        assert "key" in data

        payload = json.loads(data["payload"])

        assert "msg" in payload
        assert "type" in payload
        assert "time" in payload

        assert not "\n" in payload["msg"]

        vk = ed25519.Ed25519PublicKey.from_public_bytes(dec(data["key"]))
        vk.verify(dec(data["sig"]), data["payload"].encode())

        assert data["key"] in config["users"]

        raws.append(enc(raw))
        messages.append(payload)

        tk_print(f"{config['users'][data['key']]}: {payload['msg']}")
#    except:
#        pass
    finally: pass

    try:
        client.close()
    except:
        pass

def server_daemon():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", pseed + 9000))
    sock.listen(64)

    while True:
        client, _ = sock.accept()
        threading.Thread(target=client_handler, args=(client,), daemon=True).start()
threading.Thread(target=server_daemon, daemon=True).start()

def flush():
    if not "FLUSH" in os.environ:
        return

    with open(os.path.join("secret", "chat_messages"), "w") as f:
        f.write(json.dumps(messages))

    with open(os.path.join("secret", "chat_raws"), "w") as f:
        f.write(json.dumps(raws))
atexit.register(flush)

def flush_daemon():
    while True:
        time.sleep(60)
        flush()
threading.Thread(target=flush_daemon, daemon=True).start()

def send_raw(raw, node):
    try:
        sock = socks.socksocket()
        sock.set_proxy(socks.SOCKS5, "localhost", pseed + 9001)
        sock.settimeout(10)
        sock.connect((node, 1337))

        private_key = X25519PrivateKey.generate()
        sock.sendall(private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
        peer_public_key = X25519PublicKey.from_public_bytes(sock.recv(32))
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data").derive(shared_key)
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(bytes(16)))
        encryptor = cipher.encryptor()

        sock.sendall(encryptor.update(raw.encode() + bytes(16 - len(raw.encode()) % 16)) + encryptor.finalize())
        sock.close()
    except:
        print(f"node {node} is offline")
        sys.stdout.flush()

        send.configure(bg="red")
        time.sleep(0.5)
        send.configure(bg="white")
    

def send_message(msg):
    payload = {}
    payload["msg"] = msg
    payload["type"] = "text/plain"
    payload["time"] = int(time.time())

    data = {}
    data["payload"] = json.dumps(payload)
    data["key"] = enc(vk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    data["sig"] = enc(sk.sign(data["payload"].encode()))

    raw = json.dumps(data)

    for node in config["nodes"]:
        send_raw(raw, node)

def tk_send(*args, **kwargs):
    if len(inp.get().strip()) == 0:
        return

    threading.Thread(target=send_message, args=(inp.get(),)).start()
    inp.delete(0, "end")

def tk_print(msg):
    txt.configure(state='normal')
    txt.insert("end", msg + "\n")
    txt.see(tkinter.END)
    txt.configure(state='disabled')

root = tkinter.Tk()
txt = tkinter.scrolledtext.ScrolledText(root, undo=True)
txt['font'] = ('consolas', '12')
txt.config(state="disabled")
txt.pack(expand=True, fill='both')
txt.bind("<1>", lambda event: txt.focus_set())

inp = tkinter.Entry(root)
inp.bind("<Return>", tk_send)
inp.pack(expand=True, fill='both')
send = tkinter.Button(root, text="Send", command=tk_send)
send.pack(expand=True, fill='both')

root.mainloop()
