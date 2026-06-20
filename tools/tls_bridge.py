import argparse
import asyncio
import ssl
from contextlib import suppress


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        with suppress(Exception):
            writer.close()
            await writer.wait_closed()


async def handle_client(client_reader, client_writer, backend_host, backend_port):
    backend_reader, backend_writer = await asyncio.open_connection(backend_host, backend_port)
    await asyncio.gather(
        pipe(client_reader, backend_writer),
        pipe(backend_reader, client_writer),
    )


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="::1")
    parser.add_argument("--listen-port", type=int, default=2443)
    parser.add_argument("--backend-host", default="::1")
    parser.add_argument("--backend-port", type=int, default=1443)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)

    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, args.backend_host, args.backend_port),
        host=args.listen_host,
        port=args.listen_port,
        ssl=ctx,
    )

    sockets = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
    print(f"TLS bridge listening on {sockets} -> {args.backend_host}:{args.backend_port}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
