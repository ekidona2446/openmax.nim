import argparse
import asyncio
import hashlib
import sqlite3
import ssl
from pathlib import Path

from pymax.protocol import OutboundFrame
from pymax.protocol.tcp import TcpProtocol
from pymax.protocol.tcp.framing import TcpPacketFramer


async def invoke(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, protocol: TcpProtocol, frame: OutboundFrame):
    writer.write(protocol.encode(frame))
    await writer.drain()

    framer = TcpPacketFramer()
    header = await reader.readexactly(framer.HEADER_SIZE)
    payload_len = framer.unpack_header(header)
    if payload_len is None:
        raise RuntimeError("failed to read tcp header")
    payload = await reader.readexactly(payload_len)
    return protocol.decode(header + payload)


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
    parser.add_argument("--host", default="::1")
    parser.add_argument("--port", type=int, default=19443)
    parser.add_argument("--db", default=str(Path(__file__).resolve().parents[1] / "pymax-tcp-tls.db"))
    parser.add_argument("--phone", default="+7 999 000 10 01")
    parser.add_argument("--ca-cert", default="")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif args.ca_cert:
        ctx.load_verify_locations(args.ca_cert)

    reader, writer = await asyncio.open_connection(
        args.host,
        args.port,
        ssl=ctx,
        server_hostname=None if args.insecure else args.host,
    )
    protocol = TcpProtocol()

    hello = {
        "clientSessionId": 1,
        "mt_instanceid": "pymax-tcp-tls-probe",
        "deviceId": "pymax-tcp-tls-dev",
        "userAgent": {
            "deviceType": "ANDROID",
            "appVersion": "26.14.1",
            "osVersion": "14",
            "timezone": "Europe/Moscow",
            "screen": "1080x2400",
            "pushDeviceType": "GCM",
            "locale": "ru_RU",
            "deviceName": "PyMax TCP TLS Probe",
            "deviceLocale": "ru_RU",
        },
    }

    resp = await invoke(reader, writer, protocol, OutboundFrame(ver=10, cmd=0, seq=1, opcode=6, payload=hello))
    print("SESSION_INIT:", resp.model_dump())

    auth_request = await invoke(
        reader,
        writer,
        protocol,
        OutboundFrame(ver=10, cmd=0, seq=2, opcode=17, payload={"phone": args.phone, "type": "START_AUTH", "language": "ru"}),
    )
    print("AUTH_REQUEST:", auth_request.model_dump())

    token = auth_request.payload["token"]
    code = fetch_code(args.db, token)

    auth = await invoke(
        reader,
        writer,
        protocol,
        OutboundFrame(ver=10, cmd=0, seq=3, opcode=18, payload={"verifyCode": code, "authTokenType": "CHECK_CODE", "token": token}),
    )
    print("AUTH:", auth.model_dump())

    confirm = await invoke(
        reader,
        writer,
        protocol,
        OutboundFrame(ver=10, cmd=0, seq=4, opcode=23, payload={"firstName": "TlsTcp", "lastName": "Probe", "token": token, "tokenType": "REGISTER"}),
    )
    print("AUTH_CONFIRM:", confirm.model_dump())

    login_token = confirm.payload["token"]
    login = await invoke(
        reader,
        writer,
        protocol,
        OutboundFrame(ver=10, cmd=0, seq=5, opcode=19, payload={"token": login_token, "interactive": True}),
    )
    print("LOGIN:", login.model_dump())

    writer.close()
    await writer.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
