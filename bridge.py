#!/usr/bin/env python

import ssl
import asyncio
import irc
import logging
import time

import mumble


async def main():

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    m_conn_r, m_conn_w = await asyncio.open_connection(
        'junkcc.net', 64738, ssl=True
        #'localhost', 64738, ssl=ssl_ctx
    )
    i_conn_r, i_conn_w = await asyncio.open_connection('irc.freenode.net', 6667)

    await asyncio.gather(
        mumble.initConnection(m_conn_r, m_conn_w, 'test', 'Hakierspejs'),
        irc.initConnection(
            i_conn_r, i_conn_w, b'hakierspejs-2137', b'hakierspejs-testy'
        )
    )

    last_mumble_ping = time.time()
    mumble_wait = asyncio.create_task(
        mumble.listen(m_conn_r, m_conn_w, last_mumble_ping)
    )
    irc_wait = asyncio.create_task(irc.listen(i_conn_r, i_conn_w))

    while True:

        waits = {mumble_wait, irc_wait}
        await asyncio.wait(waits, timeout=1)

        if mumble_wait.done():
            mumble_msg, last_mumble_ping = await mumble_wait
            if type(mumble_msg) != mumble.pb2.UDPTunnel:
                print(str(type(mumble_msg)))
                if repr(mumble_msg):
                    print(repr(mumble_msg))
            mumble_wait = asyncio.create_task(
                mumble.listen(m_conn_r, m_conn_w, last_mumble_ping)
            )
        if irc_wait.done():
            irc_msg = await irc_wait
            print(repr(irc_msg))
            irc_wait = asyncio.create_task(irc.listen(i_conn_r, i_conn_w))

if __name__ == '__main__':
    #logging.basicConfig(level='DEBUG')
    asyncio.run(main())
