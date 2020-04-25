#!/usr/bin/env python2

import platform
import socket
import ssl
import string
import struct
import sys
import thread
import threading
import time
import traceback

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



def log(*args, **kwargs):
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


class MumbleConnection:

    def __init__(self, hostname, port, nickname, channel, password, name,
                 loglevel):

        self._sendingLock = threading.Lock()

        self._loglevel = loglevel
        # are we currently connected, and have all initial packages been sent?
        self._connected = False
        # is the connection currently fully established?
        # (does it allow sending messages?)
        self._established = False
        # bot name (mainly for logging)
        self._name = name

        # the following lists are callback functions that will be invoked...
        # on text message receipt
        self._textCallback = []
        # on connection establishment
        self._connectionEstablishedCallback = []
        # on connection loss
        self._connectionLostCallback = []
        # on connection attempt failure
        self._connectionFailedCallback = []

        self._hostname = hostname
        self._port = port
        self._nickname = nickname
        self._channel = channel
        self._password = password

        # channel id lookup table
        self._channelIds = {}
        # user id lookup table (and reverse)
        self._users = {}
        self._userIds = {}
        # current session and channel id
        self._session = None

        self._socket = None
        # contains all received, but uninterpreted data.
        self._readBuffer = ""


    def registerTextCallback(self, function):
        self._textCallback.append(function)

    def registerConnectionEstablishedCallback(self, function):
        self._connectionEstablishedCallback.append(function)

    def registerConnectionLostCallback(self, function):
        self._connectionLostCallback.append(function)

    def registerConnectionFailedCallback(self, function):
        self._connectionFailedCallback.append(function)

    def _invokeTextCallback(self, sender, message):
        for f in self._textCallback:
            f(sender, message)

    def _invokeConnectionEstablishedCallback(self):
        for f in self._connectionEstablishedCallback:
            f()

    def _invokeConnectionLostCallback(self):
        for f in self._connectionLostCallback:
            f()

    def _invokeConnectionFailedCallback(self):
        for f in self._connectionFailedCallback:
            f()

    def start(self):
        thread.start_new_thread(self.run, ())

    def stop(self):
        self._connected = False
        self._established = False

    def _connectionEstablished(self):
        """
        MUST be called manually, as soon as the connection is ready to
        transmit text messages.
        """
        if not self._connected:
            raise Exception("connection can't be established, since it's " +
                            "not even connected")
        self._established = True
        self._invokeConnectionEstablishedCallback()

    def run(self):
        """
        opens and initializes the connection, contains the listening loop,
        and closes the connection.
        """
        self._openConnection()
        self._initConnection()

        self._connected = True
        self._postConnect()

        while self._connected:
            self._listen()

        self._established = False
        self._connected = False

        self._closeConnection()
        self._invokeConnectionLostCallback()

    def _sendMessage(self, message):
        """
        sends a message, taking care of thread-safety and error handling.
        calls _sendMessageUnsafe to do the actual job; overload that.
        """
        with self._sendingLock:
            self._sendMessageUnsafe(message)
            return True

    def sendTextMessage(self, message):
        if not self._established:
            raise Exception("connection not established")
        if not self._sendTextMessageUnsafe(message):
            raise Exception("unknown error")

    def _log(self, message, level):
        if(self._loglevel >= level):
            for line in message.split('\n'):
                output = "(" + str(level) + ") " + self._name + ":"
                output = output.ljust(15)
                output = output + try_encode(line, 'utf-8')
                print(output)

    def _logException(self, message, level):
        self._log(message + ": " + str(sys.exc_info()[0]), level)
        self._log(traceback.format_exc(), level + 1)



    def _openConnection(self):
        # TODO: support server certificate validation, provide client cert
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self._hostname, self._port))
            self._log("trying python default ssl socket", 3)
            self._socket = ssl.wrap_socket(s)
            return True
        except ssl.SSLError:
            s.close()

        try:
            self._log("python default ssl connection failed, trying TLSv1", 2)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self._hostname, self._port))
            self._socket = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
            return True
        except ssl.SSLError:
            s.close()
            raise Exception("Error setting up the SSL/TLS socket to murmur.")

    def _initConnection(self):
        pbMess = pb2.Version()
        pbMess.release = "1.2.6"
        pbMess.version = 0x010206  # int32
        pbMess.os = platform.system()
        pbMess.os_version = "mumblebot lol"
        if not self._sendMessage(pbMess):
            raise Exception("couldn't send version package", 0)
        pbMess = pb2.Authenticate()
        pbMess.username = self._nickname
        if self._password is not None:
            pbMess.password = self._password
        pbMess.opus = True
        if not self._sendMessage(pbMess):
            raise Exception("couldn't send auth package", 0)
        return True

    def _postConnect(self):
        thread.start_new_thread(self._pingLoop, ())
        return True

    def _closeConnection(self):
        self._channelId = None
        self._session = None
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()
        return True

    def _listen(self):
        header = self._socket.recv(6)
        if len(header) == 6:
            (mid, size) = struct.unpack(">HI", header)
        else:
            raise Exception("expected 6 bytes, but got " + str(len(header)))

        data = bytearray()
        while len(data) < size:
            data.extend(self._socket.recv(size - len(data)))

        if mid not in messageTypes:
            return
        messagetype = messageTypes[mid]
        pbMess = messagetype()

        if messagetype != pb2.UDPTunnel:
            pbMess.ParseFromString(data)

        if messagetype == pb2.ServerSync:
            self._log("server sync package received. session=" +
                      str(pbMess.session), 1)
            self._session = pbMess.session
            self._joinChannel(self._channel)
        elif messagetype == pb2.ChannelState:
            self._log("channel state package received", 2)
            if(pbMess.name):
                self._log("channel " + pbMess.name + " has id " +
                          str(pbMess.channel_id), 2)
                self._channelIds[pbMess.name] = pbMess.channel_id
        elif messagetype == pb2.TextMessage:
            sender = self._users[pbMess.actor]
            self._log("text message received, sender: " + sender, 2)
            self._invokeTextCallback(sender, pbMess.message)
        elif messagetype == pb2.UserState:
            self._log("user state package received.", 2)
            if(pbMess.name and pbMess.session):
                self._users[pbMess.session] = pbMess.name
                self._userIds[pbMess.name] = pbMess.session
                self._log("user " + pbMess.name + " has id " +
                          str(pbMess.session), 2)

            if ((pbMess.channel_id is not None and
                 pbMess.session == self._session)):

                self._channelId = pbMess.channel_id
                self._log("I was dragged into another channel. Channel id:" +
                          str(pbMess.channel_id), 2)

                self._connectionEstablished()

        return True

    def _sendMessageUnsafe(self, message):
        stringMessage = message.SerializeToString()
        length = len(stringMessage)
        header = struct.pack(">HI", message.typeID, length)
        packedMessage = header + stringMessage
        while len(packedMessage) > 0:
            sent = self._socket.send(packedMessage)
            if sent < 0:
                raise Exception("could not send message")
            packedMessage = packedMessage[sent:]
        return True

    def _sendTextMessageUnsafe(self, message):
        pbMess = pb2.TextMessage()
        pbMess.session.append(self._session)
        pbMess.channel_id.append(self._channelId)
        pbMess.message = message
        self._log("sending text message: " + message, 2)
        return self._sendMessage(pbMess)

    def _pingLoop(self):
        while self._connected:
            pbMess = pb2.Ping()
            if not self._sendMessage(pbMess):
                self._log("failed to send ping message", 1)
            time.sleep(10)

    def _joinChannel(self, channel):
        if not self._session:
            self._log("can't join channel: no valid session id", 1)
            return False

        cid = self._channelIds[channel]
        self._log("sending package to join channel " + channel +
                  " (id " + str(cid) + ")", 2)

        pbMess = pb2.UserState()
        pbMess.session = self._session
        pbMess.channel_id = cid
        if not self._sendMessage(pbMess):
            self._log("failed to send join package", 1)
            return False

        self._channelId = cid
        self._connectionEstablished()

    def setComment(self, message=""):
        if not self._session:
            self._log("can't set comment to %s: no valid session id"
                      % message, 1)
            return False

        if not self._established:
            self._log("can't set comment to %s: connection not established"
                      % message, 1)
            return False

        if len(message) > 128:
            self._log("can't set comment: too long (>128 bytes)", 1)
            return False

        pbMess = pb2.UserState()
        pbMess.session = self._session
        pbMess.comment = message
        pbMess.channel_id = self._channelId
        if not self._sendMessage(pbMess):
            self._log("failed to send comment package", 1)
            return False

        return True


def main():
    mumble = MumbleConnection(
        'junkcc.net',
        64738,
        'zdzislaw_bot',
        'Hakierspejs',
        '',
        "mumble",
        3)

    mumble.run()


if __name__ == "__main__":
    main()
