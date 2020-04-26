#!/usr/bin/env python2

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


async def listen(conn):
    header = await conn.read(6)
    if len(header) == 6:
        (mid, size) = struct.unpack(">HI", header)
    else:
        raise Exception("expected 6 bytes, but got " + str(len(header)))

    data = bytearray()
    while len(data) < size:
        data.extend(await conn.read(size - len(data)))

    if mid not in messageTypes:
        return
        raise Exception('Unexpected message type: %r' % mid)
    messagetype = messageTypes[mid]
    msg = messagetype()

    if messagetype != pb2.UDPTunnel:
        msg.ParseFromString(data)

    return msg


async def main():

    conn_r, conn_w = await asyncio.open_connection(
        'junkcc.net', 64738, ssl=True
    )
    await initConnection(conn_w, 'test')

    while True:
        msg = await listen(conn_r)
        print(msg)


if __name__ == "__main__":
    asyncio.run(main())
