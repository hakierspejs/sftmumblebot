import asyncio
import logging


async def initConnection(sock_r, sock_w, nickname, channel):
    sock_w.write(b"NICK %s\n" % nickname)
    sock_w.write(b"USER %s %s bla :%s\n" % (nickname, nickname, nickname))
    await sock_w.drain()
    while True:
        msg = await listen(sock_r, sock_w)
        if msg[1] == b"001":
            break
    sock_w.write(b"JOIN #%s\n" % channel)
    await sock_w.drain()


async def listen(conn_r, conn_w):
    while True:
        line = await conn_r.readline()
        line = line.rstrip().split(b' ', 3)
        if len(line) < 2:
            continue
        if line[0] == b"PING":
            conn_w.write(b"PONG " + line[1])
            await conn_w.drain()
        if len(line) < 4:
            continue
        return line


async def main():
    conn_r, conn_w = await asyncio.open_connection('irc.freenode.net', 6667)
    await initConnection(conn_r, conn_w, b'hakierspejs-2137', b'hakierspejs-testy')
    while True:
        msg = await listen(conn_r, conn_w)
        print(msg)


if __name__ == '__main__':
    logging.basicConfig(level='DEBUG')
    asyncio.run(main())
