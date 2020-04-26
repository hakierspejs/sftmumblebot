#!/usr/bin/env python

import ssl
import asyncio
import mumble
import irc
import logging


async def main():

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    conn_r, conn_w = await asyncio.open_connection(
        #'junkcc.net', 64738, ssl=True
        'localhost', 64738, ssl=ssl_ctx
    )
    i_conn_r, i_conn_w = await asyncio.open_connection('irc.freenode.net', 6667)

    await asyncio.gather(
        mumble.initConnection(conn_w, 'test'),
        irc.initConnection(
            i_conn_r, i_conn_w, b'hakierspejs-2137', b'hakierspejs-testy'
        )
    )

    mumble_wait = asyncio.create_task(mumble.listen(conn_r, conn_w))
    irc_wait = asyncio.create_task(irc.listen(i_conn_r, i_conn_w))

    while True:

        waits = {mumble_wait, irc_wait}
        await asyncio.wait(waits, timeout=1)

        if mumble_wait.done():
            mumble_msg = await mumble_wait
            print(mumble_msg)
            mumble_wait = asyncio.create_task(mumble.listen(conn_r, conn_w))
        if irc_wait.done():
            irc_msg = await irc_wait
            print(irc_msg)
            irc_wait = asyncio.create_task(irc.listen(i_conn_r, i_conn_w))

if __name__ == '__main__':
    #logging.basicConfig(level='DEBUG')
    asyncio.run(main())
