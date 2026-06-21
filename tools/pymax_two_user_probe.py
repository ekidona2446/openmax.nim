import argparse
import asyncio
import hashlib
import shutil
import sqlite3
from pathlib import Path

from pymax.auth.providers import SmsCodeProvider
from pymax.client import Client
from pymax.config import ExtraConfig, RegistrationConfig
from pymax.protocol.enums import Opcode


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
        raise RuntimeError(f"No auth code found for {phone}")


def make_client(args, phone: str, work_dir: str, first_name: str) -> Client:
    return Client(
        phone=phone,
        work_dir=work_dir,
        extra_config=ExtraConfig(
            host=args.host,
            port=args.port,
            use_ssl=False,
            telemetry=False,
            reconnect=False,
            log_level=args.log_level,
            registration_config=RegistrationConfig(first_name=first_name, last_name="User"),
        ),
        sms_code_provider=DbSmsCodeProvider(args.db),
    )


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="::1")
    parser.add_argument("--port", type=int, default=1443)
    parser.add_argument("--db", default=str(Path(__file__).resolve().parents[1] / "pymax.db"))
    parser.add_argument("--phone", action="append", default=["+7 999 000 00 01", "+7 999 000 00 02"])
    parser.add_argument("--work-root", default="/tmp/openmax-two-user-probe")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    if len(args.phone) != 2:
        raise RuntimeError("Pass exactly two --phone values")

    shutil.rmtree(args.work_root, ignore_errors=True)
    Path(args.work_root).mkdir(parents=True, exist_ok=True)

    c1 = make_client(args, args.phone[0], str(Path(args.work_root) / "u1"), "Alice")
    c2 = make_client(args, args.phone[1], str(Path(args.work_root) / "u2"), "Bob")
    bob_events = []
    bob_typing_events = []

    @c2.on_message()
    async def on_bob_message(message, client):
        bob_events.append(message)
        print("bob-event", message.model_dump())

    @c2.on_typing()
    async def on_bob_typing(event, client):
        bob_typing_events.append(event)
        print("bob-typing", event.model_dump())

    await c1._app.start()
    await c2._app.start()

    try:
        u1 = c1.me.contact
        u2 = c2.me.contact
        print("registered", {"u1": u1.model_dump(), "u2": u2.model_dump()})

        found2 = await c1.search_by_phone(args.phone[1])
        found1 = await c2.search_by_phone(args.phone[0])
        print("found", {"c1_found": found2.model_dump(), "c2_found": found1.model_dump()})

        contact2 = await c1.add_contact(found2.id)
        contact1 = await c2.add_contact(found1.id)
        print("contacts-added", {"c1": contact2.model_dump(), "c2": contact1.model_dump()})
        contact_list_1 = await c1._app.invoke(Opcode.CONTACT_LIST, {})
        contact_list_2 = await c2._app.invoke(Opcode.CONTACT_LIST, {})
        print("contact-list", {"c1": contact_list_1.payload, "c2": contact_list_2.payload})

        fetched_by_id = await c1.get_user(found2.id)
        print("fetch-by-id", fetched_by_id.model_dump() if fetched_by_id else None)

        chat_id = c1.get_chat_id(u1.id, u2.id)
        print("dialog-chat-id", chat_id)

        await c1._app.invoke(Opcode.MSG_TYPING, {"chatId": chat_id, "type": "TYPING"})
        await asyncio.sleep(0.2)

        sent = await c1.send_message(chat_id, "hello Bob from Alice", notify=False)
        print("sent", sent.model_dump() if sent else None)
        await asyncio.sleep(0.5)

        h1 = await c1.fetch_history(chat_id, backward=10)
        h2 = await c2.fetch_history(chat_id, backward=10)
        print("history-c1", [m.model_dump() for m in h1 or []])
        print("history-c2", [m.model_dump() for m in h2 or []])

        chats1 = await c1.fetch_chats()
        chats2 = await c2.fetch_chats()
        print("chats-c1", [c.model_dump() for c in chats1])
        print("chats-c2", [c.model_dump() for c in chats2])

        assert sent is not None
        assert any(m.id == sent.id for m in h1 or [])
        assert any(m.id == sent.id for m in h2 or [])
        assert any(c.id == chat_id for c in chats1)
        assert any(c.id == chat_id for c in chats2)
        assert any(getattr(m, "id", None) == sent.id for m in bob_events), "Bob did not receive NOTIF_MESSAGE"
        assert bob_typing_events, "Bob did not receive NOTIF_TYPING"
        assert contact_list_1.payload.get("contacts"), "Alice contact list is empty"
        assert contact_list_2.payload.get("contacts"), "Bob contact list is empty"
        print("two-user-probe ok")
    finally:
        await c1.close()
        await c2.close()


if __name__ == "__main__":
    asyncio.run(main())
