import asyncio
import json
import os
import websockets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

send_session_keys = {}
recv_session_keys = {}

public_key_cache = {}
public_key_waiters = {}

def load_public_key(pem_text: str):
    return serialization.load_pem_public_key(pem_text.encode())

async def get_peer_public_key(ws, peer_user_id):
    if peer_user_id in public_key_cache:
        return public_key_cache[peer_user_id]

    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    public_key_waiters[peer_user_id] = fut

    await ws.send(json.dumps({
        "type": "get_public_key",
        "user_id": peer_user_id
    }))

    try:
        return await asyncio.wait_for(fut, timeout=5.0)
    except asyncio.TimeoutError:
        print(f"\n❌ Timeout getting public key for {peer_user_id}. Are they online?")
        public_key_waiters.pop(peer_user_id, None)
        return None

async def ensure_session(ws, peer_user_id):
    if peer_user_id in send_session_keys:
        return True

    peer_public_key = await get_peer_public_key(ws, peer_user_id)
    if not peer_public_key:
        return False

    session_key = AESGCM.generate_key(bit_length=128)
    send_session_keys[peer_user_id] = session_key

    encrypted_session_key = peer_public_key.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    signature = private_key.sign(
        encrypted_session_key,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    await ws.send(json.dumps({
        "type": "session_key",
        "to": peer_user_id,
        "encrypted_key": encrypted_session_key.hex(),
        "signature": signature.hex()
    }))
    return True

async def send_messages(ws):
    while True:
        to_user = await asyncio.to_thread(input, "\nSend to: ")
        if not to_user.strip():
            continue
            
        message = await asyncio.to_thread(input, "Message: ")

        if to_user not in send_session_keys:
            success = await ensure_session(ws, to_user)
            if not success:
                continue

        key = send_session_keys.get(to_user)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

        data_to_sign = nonce + ciphertext
        signature = private_key.sign(
            data_to_sign,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        await ws.send(json.dumps({
            "type": "message",
            "to": to_user,
            "nonce": nonce.hex(),
            "payload": ciphertext.hex(),
            "signature": signature.hex()
        }))
        
        print(f"✅ Message sent to {to_user}")

async def receive_messages(ws):
    while True:
        try:
            raw = await ws.recv()
            data = json.loads(raw)
            msg_type = data.get("type")

            if msg_type == "error" or "error" in data:
                print(f"\n❌ Server Error: {data.get('error', 'Unknown error')}")
                error_user = data.get("user_id")
                if error_user and error_user in public_key_waiters:
                    fut = public_key_waiters.pop(error_user)
                    if not fut.done():
                        fut.set_result(None)
                continue

            if msg_type == "public_key":
                peer_user_id = data["user_id"]
                peer_public_key = load_public_key(data["public_key"])
                public_key_cache[peer_user_id] = peer_public_key

                fut = public_key_waiters.pop(peer_user_id, None)
                if fut and not fut.done():
                    fut.set_result(peer_public_key)
                continue

            if msg_type == "session_key":
                sender = data["from"]
                encrypted_key = bytes.fromhex(data["encrypted_key"])
                signature = bytes.fromhex(data["signature"])

                sender_pem = data["sender_public_key"]
                if sender not in public_key_cache:
                    public_key_cache[sender] = load_public_key(sender_pem)
                sender_public_key = public_key_cache[sender]

                try:
                    sender_public_key.verify(
                        signature,
                        encrypted_key,
                        asym_padding.PSS(
                            mgf=asym_padding.MGF1(hashes.SHA256()),
                            salt_length=asym_padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                except Exception:
                    print(f"\n⚠️ Invalid session key signature from {sender}")
                    continue

                try:
                    session_key = private_key.decrypt(
                        encrypted_key,
                        asym_padding.OAEP(
                            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                except Exception:
                    print(f"\n⚠️ Could not decrypt session key from {sender}")
                    continue

                recv_session_keys[sender] = session_key
                print(f"\n🔐 Session key established with {sender}")
                continue

            if msg_type == "message":
                sender = data["from"]
                nonce = bytes.fromhex(data["nonce"])
                payload = bytes.fromhex(data["payload"])
                signature = bytes.fromhex(data["signature"])

                sender_public_key = public_key_cache.get(sender)
                
                if not sender_public_key:
                    print(f"\n No cached public key for {sender}")
                    continue

                try:
                    data_to_verify = nonce + payload
                    sender_public_key.verify(
                        signature,
                        data_to_verify,
                        asym_padding.PSS(
                            mgf=asym_padding.MGF1(hashes.SHA256()),
                            salt_length=asym_padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                except Exception:
                    print(f"\n⚠️ Invalid message signature from {sender}")
                    continue

                key = recv_session_keys.get(sender)
                if not key:
                    print(f"\n⚠️ No session key from {sender} yet.")
                    continue

                aesgcm = AESGCM(key)

                try:
                    decrypted_message = aesgcm.decrypt(nonce, payload, None).decode()
                except Exception:
                    print(f"\n⚠️ AES decryption failed from {sender}")
                    continue

                print(f"\n📩 {sender}: {decrypted_message}")
                continue

        except websockets.exceptions.ConnectionClosed:
            print("\n❌ Disconnected from server.")
            break

async def chat():
    uri = "ws://localhost:8765"
    try:
        async with websockets.connect(uri) as ws:
            user_id = await asyncio.to_thread(input, "Enter your name: ")

            await ws.send(json.dumps({
                "type": "register",
                "user_id": user_id,
                "public_key": public_pem
            }))

            print(f"your req for registeration of user {user_id} has been sent to the server")

            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=5)
                response = json.loads(raw)

                if response.get("type") == "register_success":
                    print(f"✅ Connected as {user_id}")
                elif response.get("type") == "register_error":
                    print(f"❌ Registration failed: {response.get('error')}")
                    return
                else:
                    print("❌ Unexpected response from server")
                    return

            except asyncio.TimeoutError:
                print("❌ Server did not respond (timeout)")
                return
            
            await asyncio.gather(
                send_messages(ws),
                receive_messages(ws)
            )
    except ConnectionRefusedError:
        print("❌ Cannot connect to the server. Is the server running?")

if __name__ == "__main__":
    try:
        asyncio.run(chat())
    except KeyboardInterrupt:
        print("\nExiting...")