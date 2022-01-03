# Socket communication protocol


## Server 
```python
import socket
import logging
import asyncio
from SocketDTP.SDTP import SDTP


class Server(SDTP):
    def __init__(self):
        logging.basicConfig(level=logging.DEBUG)
        self.logServer = logging.getLogger('Server')

        self.loop = asyncio.get_event_loop()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('localhost', 2324))
        self.socket.listen()

        super(Server, self).__init__()
        self.GenPG()

    def clientClose(self, client, client_address: tuple, error: str = 'No'):
        self.logServer.info(f'Client close: {client_address}, Error: {error}')
        client.close()

    async def recvToSend(self, client, client_address: tuple, message_key: str, mac_key: str):
        while True:
            try:
                recv = await self.encRecvAsync(self.loop, client, message_key, mac_key)
                if recv:
                    if recv['type'] == 'message':
                        await self.encSendAsync(self.loop, client, message_key, mac_key, recv['data']['message'])
                else:
                    self.clientClose(client, client_address)
                    break
            except Exception as e:
                self.clientClose(client, client_address, e.args[1])
                client.close()
                break

    async def accept(self):
        while True:
            client, client_address = await self.loop.sock_accept(self.socket)
            self.logServer.info(f'Client connect: {client_address}')

            message_key, mac_key = self.enc_key(client, 2)
            message_key, mac_key = str(message_key), str(mac_key)
            self.logServer.info(f'Connections are protected')

            self.loop.create_task(self.recvToSend(client, client_address, message_key, mac_key))

    async def main(self):
        self.logServer.info('Start Server')
        await self.loop.create_task(self.accept())

    def run(self):
        try:
            self.loop.run_until_complete(self.main())
        except KeyboardInterrupt:
            self.logServer.info('Close Server')


if __name__ == "__main__":
    server = Server()
    server.run()
```


## Client
```python
import socket
import logging
import asyncio
from SocketDTP.SDTP import SDTP


class Client(SDTP):
    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.logClient = logging.getLogger('Client')

        self.loop = asyncio.get_event_loop()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(('localhost', 2324))

        super(Client, self).__init__()

        message_key, mac_key = self.enc_key(self.socket, 2, 'client')
        self.message_key, self.mac_key = str(message_key), str(mac_key)

    async def recvMessage(self):
        while True:
            recv = await self.encRecvAsync(self.loop, self.socket, self.message_key, self.mac_key)
            if recv:
                if recv['type'] == 'message':
                    print(f"Recv server: {recv['data']['message']}")
            else:
                self.socket.close()
                break

    async def handler(self):
        self.loop.create_task(self.recvMessage())
        while True:
            message = await self.loop.run_in_executor(None, input)
            await self.encSendAsync(self.loop, self.socket, self.message_key, self.mac_key, message)

    async def main(self):
        await self.loop.create_task(self.handler())

    def run(self):
        try:
            self.loop.run_until_complete(self.main())
        except KeyboardInterrupt:
            self.logClient.info('Close Server')


if __name__ == "__main__":
    client = Client()
    client.run()
```