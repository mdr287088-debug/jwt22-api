import json
import base64
import httpx
import asyncio
from Crypto.Cipher import AES
from google.protobuf import json_format
from proto import FreeFire_pb2

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

USERAGENT = "Dalvik/2.1.0 (Linux; Android 13)"
RELEASEVERSION = "OB52"

def pad(text: bytes) -> bytes:
    padding = AES.block_size - len(text) % AES.block_size
    return text + bytes([padding]) * padding

def aes_cbc_encrypt(key, iv, data):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data))

async def get_access_token(account):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"{account}&response_type=token&client_type=2&client_id=100067"
    headers = {"User-Agent": USERAGENT}
    async with httpx.AsyncClient() as c:
        r = await c.post(url, data=payload, headers=headers)
        j = r.json()
        return j.get("access_token","0"), j.get("open_id","0")

async def create_jwt(uid, password):
    token, open_id = await get_access_token(f"uid={uid}&password={password}")

    body = {
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token,
        "orign_platform_type": "4"
    }

    req = FreeFire_pb2.LoginReq()
    json_format.ParseDict(body, req)

    encrypted = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, req.SerializeToString())

    async with httpx.AsyncClient() as c:
        r = await c.post(
            "https://loginbp.ggblueshark.com/MajorLogin",
            data=encrypted,
            headers={
                "User-Agent": USERAGENT,
                "ReleaseVersion": RELEASEVERSION,
                "Content-Type": "application/octet-stream"
            }
        )

    res = FreeFire_pb2.LoginRes.FromString(r.content)
    return json.loads(json_format.MessageToJson(res))

def handler(request):
    uid = request.query.get("uid")
    password = request.query.get("password")

    if not uid or not password:
        return {
            "statusCode": 400,
            "body": json.dumps({"error":"uid & password required"})
        }

    data = asyncio.run(create_jwt(uid, password))
    return {
        "statusCode": 200,
        "body": json.dumps(data)
}
