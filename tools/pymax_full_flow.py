import argparse
import asyncio
import hashlib
import sqlite3
import ssl
from pathlib import Path

from pymax.client import Client
from pymax.config import ExtraConfig, RegistrationConfig
from pymax.auth.providers import SmsCodeProvider


class DbSmsCodeProvider(SmsCodeProvider):
    def __init__(self, db_path: str):
        self.db_path = db_path

    async def get_code(self, phone: str) -> str:
        normalized = "".join(ch for ch in phone if ch.isdigit())
        for _ in range(100):
            code = self._fetch_code(normalized)
            if code:
                return code
            await asyncio.sleep(0.1)
        raise RuntimeError(f"No auth code found for {phone}")

    def _fetch_code(self, phone: str) -> str | None:
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT code_hash FROM auth_tokens WHERE phone = ? ORDER BY expires DESC LIMIT 1",
            (phone,),
        ).fetchone()
        conn.close()
        if not row:
            return None
        code_hash = row[0]
        # OpenMAX stores SHA-256(code), so recover the six-digit dev code by brute force.
        for value in range(1_000_000):
            code = f"{value:06d}"
            if hashlib.sha256(code.encode()).hexdigest() == code_hash:
                return code
        return None


async def run_client(phone: str, work_dir: str, host: str, port: int, use_ssl: bool,
                     ssl_context: ssl.SSLContext | None, first_name: str, last_name: str | None,
                     db_path: str):
    client = Client(
        phone=phone,
        work_dir=work_dir,
        extra_config=ExtraConfig(
            host=host,
            port=port,
            use_ssl=use_ssl,
            ssl_context=ssl_context,
            telemetry=False,
            reconnect=False,
            log_level="DEBUG",
            registration_config=RegistrationConfig(first_name=first_name, last_name=last_name),
        ),
        sms_code_provider=DbSmsCodeProvider(db_path),
    )
    await client._app.start()
    print(f"client-started phone={phone} me={client.me.model_dump()}")
    await client.close()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="::1")
    parser.add_argument("--port", type=int, default=1443)
    parser.add_argument("--db", default=str(Path(__file__).resolve().parents[1] / "pymax.db"))
    parser.add_argument("--phone", action="append", required=True)
    parser.add_argument("--work-dir", action="append", required=True)
    parser.add_argument("--first-name", action="append", required=True)
    parser.add_argument("--last-name", action="append", default=[])
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--ca-cert", default="")
    args = parser.parse_args()

    count = len(args.phone)
    if not (len(args.work_dir) == len(args.first_name) == count):
        raise RuntimeError("phone/work-dir/first-name counts must match")

    last_names = list(args.last_name)
    while len(last_names) < count:
        last_names.append(None)

    ssl_context = None
    if args.tls:
        ssl_context = ssl.create_default_context()
        if args.insecure:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        elif args.ca_cert:
            ssl_context.load_verify_locations(args.ca_cert)

    for i in range(count):
        await run_client(
            phone=args.phone[i],
            work_dir=args.work_dir[i],
            host=args.host,
            port=args.port,
            use_ssl=args.tls,
            ssl_context=ssl_context,
            first_name=args.first_name[i],
            last_name=last_names[i],
            db_path=args.db,
        )


if __name__ == "__main__":
    asyncio.run(main())
