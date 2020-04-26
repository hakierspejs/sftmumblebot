#!/usr/bin/env python2

import socket
import ssl
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
}

for k, v in messageTypes.items():
    v.typeID = k


def openConnection(hostname, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((hostname, port))
        return ssl.wrap_socket(s)
    except ssl.SSLError:
        s.close()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((hostname, port))
        return ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
    except ssl.SSLError:
        s.close()
        raise Exception("Error setting up the SSL/TLS socket to murmur.")


def send_message(message, conn):
    stringMessage = message.SerializeToString()
    length = len(stringMessage)
    header = struct.pack(">HI", message.typeID, length)
    packedMessage = header + stringMessage
    while len(packedMessage) > 0:
        sent = conn.send(packedMessage)
        if sent < 0:
            raise Exception("could not send message")
        packedMessage = packedMessage[sent:]
    return True


def initConnection(conn, nickname):
    msg = pb2.Version()
    msg.release = "1.2.6"
    msg.version = 0x010206
    msg.os = 'Linux'
    msg.os_version = "mumblebot lol"
    send_message(msg, conn)
    msg = pb2.Authenticate()
    msg.username = nickname
    msg.opus = True
    send_message(msg, conn)


def listen(conn):
    header = conn.recv(6)
    if len(header) == 6:
        (mid, size) = struct.unpack(">HI", header)
    else:
        raise Exception("expected 6 bytes, but got " + str(len(header)))

    data = bytearray()
    while len(data) < size:
        data.extend(conn.recv(size - len(data)))

    if mid not in messageTypes:
        raise Exception('Unexpected message type: %r' % mid)
    messagetype = messageTypes[mid]
    msg = messagetype()

    if messagetype != pb2.UDPTunnel:
        msg.ParseFromString(data)

    return msg


def main():

    conn = openConnection('junkcc.net', 64738)
    initConnection(conn, 'test')

    while True:
        msg = listen(conn)
        print(msg)


if __name__ == "__main__":
    main()
