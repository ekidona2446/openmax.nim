import asyncio
import sqlite3
from pathlib import Path

from pymax.protocol import OutboundFrame
from pymax.protocol.tcp import TcpProtocol
from pymax.protocol.tcp.framing import TcpPacketFramer
from pymax.transport.tcp import TCPTransport

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "pymax.db"


async def invoke(transport: TCPTransport, protocol: TcpProtocol, frame: OutboundFrame):
    raw = protocol.encode(frame)
    await transport.send(raw)

    framer = TcpPacketFramer()
    header = await transport.recv(framer.HEADER_SIZE)
    payload_len = framer.unpack_header(header)
    if payload_len is None:
        raise RuntimeError("failed to read tcp header")
    payload = await transport.recv(payload_len)
    return protocol.decode(header + payload)


def fetch_code(token: str) -> str:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "select code_hash from auth_tokens where token_hash = ?",
        (token,),
    ).fetchone()
    conn.close()
    if not row:
        raise RuntimeError("code not found")
    return row[0]


async def main():
    transport = TCPTransport(host="::1", port=1443, proxy=None, use_ssl=False)
    protocol = TcpProtocol()
    await transport.connect()

    hello = {
        "clientSessionId": 1,
        "mt_instanceid": "pymax-probe",
        "deviceId": "pymax-dev",
        "userAgent": {
            "deviceType": "ANDROID",
            "appVersion": "26.14.1",
            "osVersion": "14",
            "timezone": "Europe/Moscow",
            "screen": "1080x2400",
            "pushDeviceType": "GCM",
            "locale": "ru_RU",
            "deviceName": "PyMax IPv6 Probe",
            "deviceLocale": "ru_RU",
        },
    }

    resp = await invoke(
        transport,
        protocol,
        OutboundFrame(ver=10, cmd=1, seq=1, opcode=6, payload=hello),
    )
    print("SESSION_INIT:", resp.model_dump())

    auth_request = await invoke(
        transport,
        protocol,
        OutboundFrame(
            ver=10,
            cmd=1,
            seq=2,
            opcode=17,
            payload={"phone": "+7 999 000 00 55", "type": "START_AUTH"},
        ),
    )
    print("AUTH_REQUEST:", auth_request.model_dump())

    token = auth_request.payload["token"]
    code = fetch_code(token)

    auth = await invoke(
        transport,
        protocol,
        OutboundFrame(
            ver=10,
            cmd=1,
            seq=3,
            opcode=18,
            payload={
                "verifyCode": code,
                "authTokenType": "SMS",
                "token": token,
            },
        ),
    )
    print("AUTH:", auth.model_dump())

    await transport.close()


if __name__ == "__main__":
    asyncio.run(main())
