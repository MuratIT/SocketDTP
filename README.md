# Socket communication protocol


## Server 
```python
	import socket
	import asyncio
	import logging
	from SocketDTP.SDTP import SDTP

	logging.basicConfig(level=logging.INFO)

	log = logging.getLogger('Server')

	loop = asyncio.get_event_loop()

	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind(('localhost', 1234))
	server.listen()

	sdtp = SDTP()

	users = list()


	def closeClient(client):
	    for user in users:
	        for key, value in user.items():
	            if client == value['socket']:
	                users.remove(user)
	                client.close()


	async def sendsMessage(client, message):
	    for user in users:
	        for key, value in user.items():
	            if client != value['socket']:
	                await sdtp.encSendAsync(loop, value['socket'], str(value['message_key']), str(value['mac_key']), message)


	async def recvToSend(client, address, message_key, mac_key):
	    while True:
	        try:
	            recv = await sdtp.encRecvAsync(loop, client, str(message_key), str(mac_key))
	            if recv['type'] == 'message':
	                await sendsMessage(client, recv['data']['message'])
	        except Exception as e:
	            log.error(e)
	            closeClient(client)
	            break


	async def Accept():
	    while True:
	        client, address = await loop.sock_accept(server)
	        message_key, mac_key = sdtp.enc_key_server(client, 2) # Encryption key exchange
	        ob_user = {
	            f'connect_{address[0]}:{address[1]}': {
	                'socket': client,
	                'message_key': message_key,
	                'mac_key': mac_key
	            }
	        }
	        users.append(ob_user)
	        loop.create_task(recvToSend(client, address, message_key, mac_key))


	async def main():
	    await loop.create_task(Accept())


	if __name__ == "__main__":
	    sdtp.GenPG()
	    loop.run_until_complete(main())

```


## Client
```python
	import socket
	import asyncio
	from SocketDTP.SDTP import SDTP


	loop = asyncio.get_event_loop()

	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.connect(('localhost', 1234))

	sdtp = SDTP()
	message_key, mac_key = sdtp.enc_key_client(client, 2) # Encryption key exchange


	async def recvMessage():
	    while True:
	        recv = await sdtp.encRecvAsync(loop, client, str(message_key), str(mac_key))
	        print(recv)


	async def sendsMessage():
	    loop.create_task(recvMessage())
	    while True:
	        message = await loop.run_in_executor(None, input)
	        await sdtp.encSendAsync(loop, client, str(message_key), str(mac_key), message)


	async def main():
	    await loop.create_task(sendsMessage())


	if __name__ == "__main__":
	    loop.run_until_complete(main())

```