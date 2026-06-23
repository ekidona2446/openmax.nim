import argparse
import asyncio
import hashlib
import sqlite3
from pathlib import Path

from pymax.auth.providers import SmsCodeProvider
from pymax.client import Client
from pymax.config import ExtraConfig, RegistrationConfig
from pymax.files import File, Photo


class DbSmsCodeProvider(SmsCodeProvider):
    def __init__(self, db_path: str):
        self.db_path = db_path

    async def get_code(self, phone: str) -> str:
        normalized = "".join(ch for ch in phone if ch.isdigit())
        for _ in range(120):
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
    parser.add_argument("--phone", default="+1 555 000 00 01")
    parser.add_argument("--work-dir", default="/tmp/pymax-file-probe")
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
            registration_config=RegistrationConfig(first_name="File", last_name="Probe"),
        ),
        sms_code_provider=DbSmsCodeProvider(args.db),
    )
    await client._app.start()
    print("country", client.me.contact.location)
    sent = await client.send_message(
        0,
        "file attach probe",
        attachments=[File(raw=b"hello file", name="hello.txt")],
        notify=False,
    )
    print("sent", sent.model_dump())
    history = await client.fetch_history(0, backward=5)
    print("history", [m.model_dump() for m in history or []])
    await client.logout()
    await client.close()
    print("file-probe ok")


if __name__ == "__main__":
    asyncio.run(main())
