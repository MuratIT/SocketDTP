import json
import struct
import asyncio
import logging


class DTP:
    def __init__(self):
        self.log = logging.getLogger('DTP')

    def message(self, types: str, data: str or dict):
        message = json.dumps({'type': types, 'data': data})
        self.log.debug(message)
        return message

    def __recv_all(self, connect: any, n: int):
        data = b''
        while len(data) < n:
            packet = connect.recv(n - len(data))
            if not packet:
                packet = None
                self.log.debug(packet)
                return packet
            data += packet
        self.log.debug(str(data))
        return data

    def send(self, socket: any, message: any):
        self.log.debug('Encode message')
        msg = message.encode()
        self.log.debug('Struct pack message')
        message = struct.pack('>I', len(msg)) + msg
        self.log.debug('Send message')
        socket.sendall(message)

    def recv(self, sock: any):
        raw_msglen = self.__recv_all(sock, 4)
        if not raw_msglen:
            raw_msglen = None
            self.log.debug(raw_msglen)
            return raw_msglen
        msglen = struct.unpack('>I', raw_msglen)[0]
        recv_all = self.__recv_all(sock, msglen)
        self.log.debug(recv_all)
        return recv_all

    class ASY_DTP:
        def __init__(self, loop: asyncio.get_event_loop):
            self.loop = loop
            self.log = logging.getLogger('Async DTP')

        async def __recv_all(self, connect: any, n: int):
            data = b''
            while len(data) < n:
                packet = await self.loop.sock_recv(connect, n - len(data))
                if not packet:
                    packet = None
                    self.log.debug(packet)
                    return packet
                data += packet
            self.log.debug(data.decode())
            return data

        async def send(self, socket: any, message: str):
            self.log.debug('Encode message')
            msg = message.encode()
            self.log.debug('Struct pack message')
            message = struct.pack('>I', len(msg)) + msg
            self.log.debug('Send message')
            await self.loop.sock_sendall(socket, message)

        async def recv(self, sock: any):
            raw_msglen = await self.__recv_all(sock, 4)
            if not raw_msglen:
                raw_msglen = None
                self.log.debug(raw_msglen)
                return raw_msglen
            msglen = struct.unpack('>I', raw_msglen)[0]
            recv_all = self.__recv_all(sock, msglen)
            self.log.debug(recv_all)
            return await recv_all