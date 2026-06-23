import argparse
import asyncio
import hashlib
import json
import sqlite3
import ssl
from pathlib import Path

import websockets


class WsRpc:
    def __init__(self, ws):
        self.ws = ws
        self.seq = 0

    async def invoke(self, opcode: int, payload=None):
        self.seq += 1
        frame = {
            "ver": 11,
            "cmd": 0,
            "seq": self.seq,
            "opcode": opcode,
            "payload": payload if payload is not None else {},
        }
        await self.ws.send(json.dumps(frame, separators=(",", ":")))
        while True:
            raw = await self.ws.recv()
            data = json.loads(raw)
            if data.get("seq") == self.seq and data.get("opcode") == opcode:
                if data.get("cmd") == 3:
                    raise RuntimeError(f"WS API error opcode={opcode}: {data.get('payload')}")
                return data
            print("event", data)


def fetch_code(db_path: str, token: str) -> str:
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT code_hash FROM auth_tokens WHERE token_hash = ?",
        (hashlib.sha256(token.encode()).hexdigest(),),
    ).fetchone()
    conn.close()
    if not row:
        raise RuntimeError("code not found")
    code_hash = row[0]
    for value in range(1_000_000):
        code = f"{value:06d}"
        if hashlib.sha256(code.encode()).hexdigest() == code_hash:
            return code
    raise RuntimeError("code hash not brute-forced")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="wss://[::1]:18444/websocket")
    parser.add_argument("--db", default=str(Path(__file__).resolve().parents[1] / "pymax-tls.db"))
    parser.add_argument("--phone", default="+7 999 000 30 01")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--ca-cert", default="")
    args = parser.parse_args()

    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif args.ca_cert:
        ctx.load_verify_locations(args.ca_cert)

    async with websockets.connect(args.url, ssl=ctx, origin="https://web.tamtam.chat") as ws:
        rpc = WsRpc(ws)
        hello = await rpc.invoke(
            6,
            {
                "deviceId": "tamtam-ws-tls-probe",
                "userAgent": {
                    "deviceType": "WEB",
                    "appVersion": "26.14.1",
                    "osVersion": "Linux",
                    "timezone": "Europe/Moscow",
                    "screen": "1080x2400 1.0x",
                    "locale": "ru",
                    "deviceName": "TamTam WS TLS Probe",
                    "deviceLocale": "ru",
                    "headerUserAgent": "TamTam WS TLS Probe",
                },
            },
        )
        print("SESSION_INIT", hello)

        auth_request = await rpc.invoke(17, {"phone": args.phone})
        print("AUTH_REQUEST", auth_request)
        token = auth_request["payload"]["verifyToken"]
        code = fetch_code(args.db, token)

        auth = await rpc.invoke(
            18,
            {"token": token, "verifyCode": code, "authTokenType": "CHECK_CODE"},
        )
        print("AUTH", auth)

        if "NEW" in auth["payload"].get("tokenAttrs", {}):
            confirm = await rpc.invoke(
                23,
                {
                    "name": "TamTam WsProbe",
                    "token": token,
                    "tokenType": "NEW",
                    "deviceType": "WEB",
                    "deviceId": "tamtam-ws-tls-probe",
                },
            )
        else:
            confirm = await rpc.invoke(
                23,
                {
                    "token": token,
                    "tokenType": "AUTH",
                    "deviceType": "WEB",
                    "deviceId": "tamtam-ws-tls-probe",
                },
            )
        print("AUTH_CONFIRM", confirm)
        login_token = confirm["payload"]["token"]

        login = await rpc.invoke(19, {"token": login_token, "interactive": True})
        print("LOGIN", login)

        calls = await rpc.invoke(158, {})
        print("OK_TOKEN", calls)

    print("tamtam-ws-tls-probe ok")


if __name__ == "__main__":
    asyncio.run(main())
