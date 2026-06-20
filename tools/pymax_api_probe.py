import argparse
import asyncio
import hashlib
import sqlite3
from pathlib import Path

from pymax.client import Client
from pymax.config import ExtraConfig, RegistrationConfig
from pymax.auth.providers import SmsCodeProvider
from pymax.protocol.enums import Opcode


class DbSmsCodeProvider(SmsCodeProvider):
    def __init__(self, db_path: str):
        self.db_path = db_path

    async def get_code(self, phone: str) -> str:
        normalized = "".join(ch for ch in phone if ch.isdigit())
        for _ in range(100):
            conn = sqlite3.connect(self.db_path)
            row = conn.execute(
                "SELECT code_hash FROM auth_tokens WHERE phone = ? ORDER BY expires DESC LIMIT 1",
                (normalized,),
            ).fetchone()
            conn.close()
            if row:
                code_hash = row[0]
                for value in range(1_000_000):
                    code = f"{value:06d}"
                    if hashlib.sha256(code.encode()).hexdigest() == code_hash:
                        return code
            await asyncio.sleep(0.1)
        raise RuntimeError("No auth code found")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="::1")
    parser.add_argument("--port", type=int, default=1443)
    parser.add_argument("--db", default=str(Path(__file__).resolve().parents[1] / "pymax.db"))
    parser.add_argument("--phone", default="+7 999 000 00 01")
    parser.add_argument("--work-dir", default="/tmp/pymax-probe")
    args = parser.parse_args()

    client = Client(
        phone=args.phone,
        work_dir=args.work_dir,
        extra_config=ExtraConfig(
            host=args.host,
            port=args.port,
            use_ssl=False,
            telemetry=False,
            reconnect=False,
            log_level="INFO",
            registration_config=RegistrationConfig(first_name="Probe", last_name="User"),
        ),
        sms_code_provider=DbSmsCodeProvider(args.db),
    )

    await client._app.start()
    print("me", client.me.model_dump() if client.me else None)
    print("sessions", [s.model_dump() for s in await client.get_sessions()])
    print("folders", (await client.get_folders()).model_dump())
    print("chats", [c.model_dump() for c in await client.fetch_chats()])
    print("self-by-phone", (await client.search_by_phone(args.phone)).model_dump())
    call_token = await client._app.invoke(Opcode.CALLS_TOKEN, {})
    print("call-token", call_token.payload)
    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
