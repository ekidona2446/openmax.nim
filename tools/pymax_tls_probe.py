import asyncio
import hashlib
import sqlite3
import ssl
from pathlib import Path

from pymax.protocol import OutboundFrame
from pymax.protocol.tcp import TcpProtocol
from pymax.protocol.tcp.framing import TcpPacketFramer
from pymax.transport.tcp import TCPTransport

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "pymax.db"
CERT_PATH = ROOT / "certs" / "localhost-cert.pem"


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
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Or: ctx.load_verify_locations(CERT_PATH)

    transport = TCPTransport(host="::1", port=2443, proxy=None, use_ssl=True, ssl_context=ctx)
    protocol = TcpProtocol()
    await transport.connect()

    hello = {
        "clientSessionId": 1,
        "mt_instanceid": "pymax-tls-probe",
        "deviceId": "pymax-dev-tls",
        "userAgent": {
            "deviceType": "ANDROID",
            "appVersion": "26.14.1",
            "osVersion": "14",
            "timezone": "Europe/Moscow",
            "screen": "1080x2400",
            "pushDeviceType": "GCM",
            "locale": "ru_RU",
            "deviceName": "PyMax TLS Probe",
            "deviceLocale": "ru_RU",
        },
    }

    resp = await invoke(
        transport,
        protocol,
        OutboundFrame(ver=10, cmd=0, seq=1, opcode=6, payload=hello),
    )
    print("SESSION_INIT:", resp.model_dump())

    auth_request = await invoke(
        transport,
        protocol,
        OutboundFrame(
            ver=10,
            cmd=0,
            seq=2,
            opcode=17,
            payload={"phone": "+7 999 000 00 77", "type": "START_AUTH"},
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
            cmd=0,
            seq=3,
            opcode=18,
            payload={
                "verifyCode": code,
                "authTokenType": "CHECK_CODE",
                "token": token,
            },
        ),
    )
    print("AUTH:", auth.model_dump())

    confirm = await invoke(
        transport,
        protocol,
        OutboundFrame(
            ver=10,
            cmd=0,
            seq=4,
            opcode=23,
            payload={
                "firstName": "Tls",
                "lastName": "User",
                "token": token,
                "tokenType": "REGISTER",
            },
        ),
    )
    print("AUTH_CONFIRM:", confirm.model_dump())

    login_token = confirm.payload["token"]
    login = await invoke(
        transport,
        protocol,
        OutboundFrame(
            ver=10,
            cmd=0,
            seq=5,
            opcode=19,
            payload={"token": login_token, "interactive": True},
        ),
    )
    print("LOGIN:", login.model_dump())

    await transport.close()


if __name__ == "__main__":
    asyncio.run(main())
