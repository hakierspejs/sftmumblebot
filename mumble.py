#!/usr/bin/env python2

import time
import ssl
import asyncio
import struct
import logging
import time

import Mumble_pb2 as pb2

messageTypes = {
    0: pb2.Version,
    1: pb2.UDPTunnel,
    2: pb2.Authenticate,
    3: pb2.Ping,
    4: pb2.Reject,
    5: pb2.ServerSync,
    6: pb2.ChannelRemove,
    7: pb2.ChannelState,
    8: pb2.UserRemove,
    9: pb2.UserState,
    10: pb2.BanList,
    11: pb2.TextMessage,
    12: pb2.PermissionDenied,
    13: pb2.ACL,
    14: pb2.QueryUsers,
    15: pb2.CryptSetup,
    16: pb2.ContextActionModify,
    17: pb2.ContextAction,
    18: pb2.UserList,
    19: pb2.VoiceTarget,
    20: pb2.PermissionQuery,
    21: pb2.CodecVersion,
    22: pb2.UserStats,
    23: pb2.RequestBlob,
    24: pb2.ServerConfig,
    25: pb2.SuggestConfig,
}

for k, v in messageTypes.items():
    v.typeID = k


async def send_message(message, conn):
    stringMessage = message.SerializeToString()
    length = len(stringMessage)
    header = struct.pack(">HI", message.typeID, length)
    conn.write(header + stringMessage)
    await conn.drain()



async def join_channel(conn_r, conn_w, channel_name):
    channel_id = None
    now = time.time()
    logging.info('Synchronizing...')
    while True:
        msg, _ = await listen(conn_r, conn_w, now)
        if type(msg) == pb2.ChannelState:
            if msg.name == channel_name:
                channel_id = msg.channel_id
        elif type(msg) == pb2.ServerSync:
            if not channel_id:
                raise RuntimeError('Invalid channel name: %r' % channel_name)
            pbMess = pb2.UserState()
            pbMess.session = msg.session
            pbMess.channel_id = channel_id
            logging.info('Joining channel...')
            await send_message(pbMess, conn_w)
            break


async def initConnection(conn_r, conn_w, nickname, channel_name):
    msg = pb2.Version()
    msg.release = "1.2.6"
    msg.version = 0x010206
    msg.os = 'Linux'
    msg.os_version = "mumblebot lol"
    await send_message(msg, conn_w)
    msg = pb2.Authenticate()
    msg.username = nickname
    msg.opus = True
    await send_message(msg, conn_w)
    await join_channel(conn_r, conn_w, channel_name)


async def maybe_send_ping(conn_w, last_ping):
    now = time.time()
    if now - last_ping > 3:
        logging.debug('sending a PING')
        await send_message(pb2.Ping(), conn_w)
        last_ping = now
    return last_ping


async def listen(conn_r, conn_w, last_ping):
    while True:
        last_ping = await maybe_send_ping(conn_w, last_ping)
        try:
            header = await asyncio.wait_for(conn_r.read(6), timeout=2)
            break
        except asyncio.TimeoutError:
            pass
    (mid, size) = struct.unpack(">HI", header)
    data = await conn_r.read(size)
    messagetype = messageTypes[mid]
    msg = messagetype()
    if messagetype != pb2.UDPTunnel:
        msg.ParseFromString(data)
    return msg, last_ping


async def main():

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    conn_r, conn_w = await asyncio.open_connection(
        'junkcc.net', 64738, ssl=True
        #'localhost', 64738, ssl=ssl_ctx
    )
    await initConnection(conn_r, conn_w, 'test', 'Hakierspejs')

    last_ping = time.time()

    while True:
        msg, last_ping = await listen(conn_r, conn_w, last_ping)
        if type(msg) != pb2.UDPTunnel:
            logging.debug('Got a message: %r\n%s', type(msg), repr(msg))


if __name__ == "__main__":
    logging.basicConfig(level='DEBUG')
    loop = asyncio.get_event_loop()
    # Blocking call which returns when the hello_world() coroutine is done
    loop.run_until_complete(main())
    loop.close()
