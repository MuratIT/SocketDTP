import json
import struct
import asyncio


class DTP:
    @staticmethod
    def message(types: str, data: str or dict):
        return json.dumps({'type': types, 'data': data})

    @staticmethod
    def __recv_all(connect: any, n: int):
        data = b''
        while len(data) < n:
            packet = connect.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    @staticmethod
    def send(socket: any, message: any):
        msg = message.encode()
        message = struct.pack('>I', len(msg)) + msg
        socket.sendall(message)

    def recv(self, sock: any):
        raw_msglen = self.__recv_all(sock, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return self.__recv_all(sock, msglen)

    class ASY_DTP:
        def __init__(self, loop: asyncio.get_event_loop):
            self.loop = loop

        async def __recv_all(self, connect: any, n: int):
            data = b''
            while len(data) < n:
                packet = await self.loop.sock_recv(connect, n - len(data))
                if not packet:
                    return None
                data += packet
            return data

        async def send(self, socket: any, message: str):
            msg = message.encode()
            message = struct.pack('>I', len(msg)) + msg
            await self.loop.sock_sendall(socket, message)

        async def recv(self, sock: any):
            raw_msglen = await self.__recv_all(sock, 4)
            if not raw_msglen:
                return None
            msglen = struct.unpack('>I', raw_msglen)[0]
            return await self.__recv_all(sock, msglen)