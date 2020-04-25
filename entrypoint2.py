#!/usr/bin/env python2

import platform
import socket
import ssl
import string
import struct
import sys

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

channelIds = {}
users = {}
userIds = {}

for k, v in messageTypes.items():
    v.typeID = k


def log(*args, **kwargs):
    pass


def joinChannel(*args, **kwargs):
    pass


def try_decode(line, preferredcodec):
    try:
        return line.decode(preferredcodec)
    except:
        pass

    try:
        if preferredcodec != 'utf-8':
            return line.decode('utf-8')
    except:
        pass

    try:
        if preferredcodec != 'latin-1':
            return line.decode('latin-1')
    except:
        pass

    try:
        return line.decode('utf-8', errors='ignore')
    except:
        # how could this even possibly fail?
        pass

    try:
        # last chance, seriously
        return line.decode('ascii', errors='ignore')
    except:
        pass

    # screw you and your retarded line.
    return "[decoding error]"


def try_encode(line, preferredcodec):
    try:
        return line.encode(preferredcodec, errors='ignore')
    except:
        pass

    try:
        return line.encode('utf-8', errors='ignore')
    except:
        pass

    try:
        return line.encode('ascii', errors='ignore')
    except:
        pass

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

def send_message(message, socket):
    stringMessage = message.SerializeToString()
    length = len(stringMessage)
    header = struct.pack(">HI", message.typeID, length)
    packedMessage = header + stringMessage
    while len(packedMessage) > 0:
        sent = socket.send(packedMessage)
        if sent < 0:
            raise Exception("could not send message")
        packedMessage = packedMessage[sent:]
    return True


def initConnection(socket, nickname):
    pbMess = pb2.Version()
    pbMess.release = "1.2.6"
    pbMess.version = 0x010206  # int32
    pbMess.os = platform.system()
    pbMess.os_version = "mumblebot lol"
    send_message(pbMess, socket)
    pbMess = pb2.Authenticate()
    pbMess.username = nickname
    pbMess.opus = True
    send_message(pbMess, socket)
    return True


def listen(socket, session, channel):
    header = socket.recv(6)
    if len(header) == 6:
        (mid, size) = struct.unpack(">HI", header)
    else:
        raise Exception("expected 6 bytes, but got " + str(len(header)))

    data = bytearray()
    while len(data) < size:
        data.extend(socket.recv(size - len(data)))

    if mid not in messageTypes:
        return
    messagetype = messageTypes[mid]
    pbMess = messagetype()

    if messagetype != pb2.UDPTunnel:
        pbMess.ParseFromString(data)

    print(pbMess)

    if messagetype == pb2.ServerSync:
        session = pbMess.session
        joinChannel(channel)
    elif messagetype == pb2.ChannelState:
        if(pbMess.name):
            log("channel " + pbMess.name + " has id " +
                      str(pbMess.channel_id), 2)
            channelIds[pbMess.name] = pbMess.channel_id
    elif messagetype == pb2.TextMessage:
        sender = users[pbMess.actor]
        log("text message received, sender: " + sender, 2)
        invokeTextCallback(sender, pbMess.message)
    elif messagetype == pb2.UserState:
        log("user state package received.", 2)
        if(pbMess.name and pbMess.session):
            users[pbMess.session] = pbMess.name
            userIds[pbMess.name] = pbMess.session
            log("user " + pbMess.name + " has id " +
                      str(pbMess.session), 2)

        if ((pbMess.channel_id is not None and
             pbMess.session == session)):

            channelId = pbMess.channel_id
            log("I was dragged into another channel. Channel id:" +
                      str(pbMess.channel_id), 2)

            connectionEstablished()

    return True




def main():

    socket = openConnection('junkcc.net', 64738)
    initConnection(socket, 'test')

    while True:
        listen(socket, None, "Hakierspejs")


if __name__ == "__main__":
    main()
