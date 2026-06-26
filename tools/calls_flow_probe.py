#!/usr/bin/env python3
"""End-to-end probe for the OpenMAX Calls API + Signaling WebSocket.

This exercises the call subsystem implemented in:
  * src/openmax/protocols/calls_http.nim       (POST /fb.do)
  * src/openmax/protocols/calls/signaling_ws.nim (WS /websocket)

It mirrors the flow documented by icyfalc0n/maxcalls @ master
(docs/api/calls.md + docs/api/singaling.md):

  1. obtain a call-token over the mobile protocol (opcode 158) via PyMax
  2. auth.anonymLogin   -> session_key + external_user_id
  3. vchat.startConversation -> signaling endpoint + TURN/STUN
  4. connect to the signaling WS, receive ServerHello
  5. (two-user mode) caller transmit-data -> callee receives transmitted-data

Two modes:
  * --self-token TOKEN : skip PyMax and feed a call-token directly (quick check
    of the HTTP + WS layer; useful while iterating on the server).
  * default            : drive PyMax to log in and call CallTokenRequest. This
    requires a registered user and the same sqlite/SMS-code plumbing the other
    pymax_*.py probes use; wiring that part is intentionally left to the caller.

Usage:
  python tools/calls_flow_probe.py --base https://[::1]:443 \
      --signaling-base wss://[::1]:81 --self-token "openmax-call:42:abc" \
      --callee-token "openmax-call:99:xyz"

Dependencies: websockets (already in tools/requirements.txt). Uses stdlib for HTTP.
"""

import argparse
import asyncio
import json
import ssl
import urllib.parse
import urllib.request

APPLICATION_KEY = "CNHIJPLGDIHBABABA"


def _insecure_ssl() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def post_form(url: str, fields: dict, insecure: bool) -> dict:
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    ctx = _insecure_ssl() if url.startswith("https") and insecure else None
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        body = resp.read().decode()
    print(f"  POST {url} [{fields.get('method')}] -> {body}")
    return json.loads(body)


def anonym_login(base: str, call_token: str, insecure: bool) -> dict:
    session_data = json.dumps({
        "auth_token": call_token,
        "client_type": "SDK_JS",
        "client_version": "1.1",
        "device_id": "550e8400-e29b-41d4-a716-446655440000",
        "version": 3,
    })
    return post_form(f"{base}/fb.do", {
        "method": "auth.anonymLogin",
        "format": "JSON",
        "application_key": APPLICATION_KEY,
        "session_data": session_data,
    }, insecure)


def start_conversation(base: str, session_key: str, conversation_id: str,
                       callee_external: str, is_video: bool, insecure: bool) -> dict:
    return post_form(f"{base}/fb.do", {
        "method": "vchat.startConversation",
        "format": "JSON",
        "application_key": APPLICATION_KEY,
        "session_key": session_key,
        "conversationId": conversation_id,
        "isVideo": "true" if is_video else "false",
        "protocolVersion": "5",
        "externalIds": callee_external,
        "payload": json.dumps({"is_video": is_video}),
    }, insecure)


async def signaling_session(endpoint: str, label: str, insecure: bool,
                            send_to=None, expect_data=None):
    import websockets  # imported lazily so --help works without the dep

    ssl_ctx = _insecure_ssl() if endpoint.startswith("wss") and insecure else None
    async with websockets.connect(endpoint, ssl=ssl_ctx,
                                  extra_headers={"Origin": "https://web.max.ru"}) as ws:
        hello_raw = await asyncio.wait_for(ws.recv(), timeout=10)
        hello = json.loads(hello_raw)
        parts = hello["conversation"]["participants"]
        print(f"  [{label}] ServerHello participants: "
              + ", ".join(f"{p['externalId']['id']}->{p['id']}" for p in parts))

        if send_to is not None:
            seq = 1
            await ws.send(json.dumps({
                "command": "transmit-data",
                "sequence": seq,
                "participantId": send_to,
                "data": f"hello-from-{label}",
                "participantType": "USER",
            }))
            print(f"  [{label}] sent transmit-data to internal id {send_to}")

        if expect_data is not None:
            while True:
                raw = await asyncio.wait_for(ws.recv(), timeout=10)
                if raw == "ping":
                    await ws.send("pong")
                    continue
                msg = json.loads(raw)
                if msg.get("notification") == "transmitted-data":
                    print(f"  [{label}] received transmitted-data: {msg['data']!r}")
                    assert msg["data"] == expect_data, "payload mismatch"
                    break
        return parts


def participant_internal_id(parts, external_id: str):
    for p in parts:
        if str(p["externalId"]["id"]) == str(external_id):
            return p["id"]
    raise RuntimeError(f"participant {external_id} not in ServerHello")


async def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True, help="Calls API base, e.g. https://[::1]:443")
    ap.add_argument("--self-token", help="caller call-token (skip PyMax)")
    ap.add_argument("--callee-token", help="callee call-token for two-user test")
    ap.add_argument("--video", action="store_true")
    ap.add_argument("--insecure", action="store_true", default=True,
                    help="skip TLS verification (default on for self-signed certs)")
    args = ap.parse_args()

    if not args.self_token:
        raise SystemExit("Provide --self-token (PyMax-driven token retrieval is "
                         "left to the integrator; see module docstring).")

    conversation_id = "550e8400-e29b-41d4-a716-446655440000"

    print("[1] caller auth.anonymLogin")
    caller = anonym_login(args.base, args.self_token, args.insecure)

    callee_external = None
    if args.callee_token:
        print("[2] callee auth.anonymLogin (so its external id is known)")
        callee = anonym_login(args.base, args.callee_token, args.insecure)
        callee_external = callee["external_user_id"]
    else:
        callee_external = caller["external_user_id"]  # self-call fallback

    print("[3] caller vchat.startConversation")
    convo = start_conversation(args.base, caller["session_key"], conversation_id,
                               callee_external, args.video, args.insecure)
    endpoint = convo["endpoint"]
    print(f"    turn={convo['turn_server']['urls']} stun={convo['stun_server']['urls']}")
    print(f"    endpoint={endpoint}")

    if not args.callee_token:
        print("[4] single-user: connect caller signaling, receive ServerHello")
        await signaling_session(endpoint, "caller", args.insecure)
        print("OK (single-user)")
        return

    # Two-user: callee needs its own endpoint. startConversation already pushed an
    # IncomingCall to the callee over the mobile protocol containing vcp.endpoint;
    # here we reconstruct it from the caller endpoint by swapping userId/token.
    # In a real client this comes from the IncomingCall notification.
    print("[4] two-user signaling: caller sends, callee receives")
    # Derive callee endpoint by parsing the caller endpoint query and replacing
    # userId/token is NOT possible (token is callee-specific & server-minted),
    # so this branch requires the callee endpoint from the IncomingCall push.
    raise SystemExit("Two-user mode needs the callee endpoint from the IncomingCall "
                     "notification (opcode 137 vcp.endpoint). Capture it via PyMax "
                     "and pass it in; the single-user path above validates the core.")


if __name__ == "__main__":
    asyncio.run(main())
