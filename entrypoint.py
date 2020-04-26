#!/usr/bin/env python2

import time
import ssl
import asyncio
import struct

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


async def initConnection(conn, nickname):
    msg = pb2.Version()
    msg.release = "1.2.6"
    msg.version = 0x010206
    msg.os = 'Linux'
    msg.os_version = "mumblebot lol"
    await send_message(msg, conn)
    msg = pb2.Authenticate()
    msg.username = nickname
    msg.opus = True
    await send_message(msg, conn)


async def read_n_bytes(conn, n):
    ret = b''
    while len(ret) < n:
        remaining = n - len(ret)
        ret += await conn.read(remaining)
    return ret



async def listen(conn_r, conn_w):
    while True:
        try:
            header = await asyncio.wait_for(conn_r.read(6), timeout=5)
            break
        except asyncio.TimeoutError:
            print('Sending ping')
            await send_message(pb2.Ping(), conn_w)
    (mid, size) = struct.unpack(">HI", header)
    data = await read_n_bytes(conn_r, size)
    messagetype = messageTypes[mid]
    msg = messagetype()
    if messagetype != pb2.UDPTunnel:
        msg.ParseFromString(data)
    return msg


async def main():

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    conn_r, conn_w = await asyncio.open_connection(
        'junkcc.net', 64738, ssl=True
    )
    await initConnection(conn_w, 'test')

    while True:
        msg = await listen(conn_r, conn_w)
        print(type(msg))
        print(msg)


if __name__ == "__main__":
    asyncio.run(main())
