import asyncio
import json
from websockets import serve
from websockets.exceptions import ConnectionClosed

# user_id -> {"ws": websocket, "public_key": pem_string}
clients = {}

async def handler(websocket):
    user_id = None

    try:
        raw = await websocket.recv()
        data = json.loads(raw)

        if data.get("type") != "register":
            await websocket.send(json.dumps({
                "type": "error",
                "error": "First message must be a register packet"
            }))
            return

        user_id = data["user_id"]
        public_key = data["public_key"]

        if user_id in clients:
            await websocket.send(json.dumps({
                "type": "register_error",
                "error": f"{user_id} is already online"
            }))
            return

        clients[user_id] = {
            "ws": websocket,
            "public_key": public_key
        }

        await websocket.send(json.dumps({
            "type": "register_success",
            "user_id": user_id
        }))

        print(f"{user_id} connected")

        async for raw in websocket:
            data = json.loads(raw)
            msg_type = data.get("type")

            if msg_type == "get_public_key":
                target = data["user_id"]

                if target in clients:
                    await websocket.send(json.dumps({
                        "type": "public_key",
                        "user_id": target,
                        "public_key": clients[target]["public_key"]
                    }))
                else:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "user_id": target,
                        "error": f"{target} is not online"
                    }))
            
            elif msg_type in ("session_key", "message"):
                to_user = data["to"]

                if to_user not in clients:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "user_id": to_user,
                        "error": f"{to_user} is not online"
                    }))
                    continue
                
                outgoing = dict(data)
                outgoing["from"] = user_id

                if msg_type == "message":
                    payload = data.get("payload", "No payload")
                    print(f"\n[ENCRYPTED MESSAGE] {user_id} -> {to_user}")
                    print(f"   ↳ Ciphertext: {payload[:60]}...")
                    
                elif msg_type == "session_key":
                    enc_key = data.get("encrypted_key", "No key")
                    print(f"\n[ENCRYPTED SESSION KEY] {user_id} -> {to_user}")
                    print(f"   ↳ Encrypted AES Key: {enc_key[:60]}...")
                    outgoing["sender_public_key"] = clients[user_id]["public_key"]



                await clients[to_user]["ws"].send(json.dumps(outgoing))

            else:
                await websocket.send(json.dumps({
                    "type": "error",
                    "error": f"Unknown message type: {msg_type}"
                }))

    except ConnectionClosed:
        pass
    except json.JSONDecodeError:
        pass
    finally:
        if user_id and clients.get(user_id, {}).get("ws") is websocket:
            del clients[user_id]

        if user_id:
            print(f"{user_id} disconnected")

async def main():
    print("Starting server...")
    async with serve(handler, "localhost", 8765):
        print("Server running on ws://localhost:8765")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
