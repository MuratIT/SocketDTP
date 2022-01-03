from Crypto.Random.random import getrandbits
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto import Random
from .DTP import DTP
import hashlib
import asyncio
import base64
import json


class SDTP(DTP):
    def __init__(self, pg: tuple = (0, 0), byte: int = 1024):
        super(SDTP, self).__init__()

        self.pg = pg
        self.byte = byte

    class __DH:
        @staticmethod
        def PublicKey(g: int, privateKey: int, p: int):
            return pow(g, privateKey, p)

        @staticmethod
        def SharedSecretKey(PublicKey: int, privateKey: int, p: int):
            return pow(PublicKey, privateKey, p)

    class __AESCipher:
        def __init__(self, key: str):
            self.bs = AES.block_size
            self.key = hashlib.sha256(key.encode()).digest()

        def Encrypt(self, raw: str):
            raw = pad(raw.encode('utf-8'), self.bs)
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return base64.b64encode(iv + cipher.encrypt(raw))

        def Decrypt(self, enc: bytes):
            enc = base64.b64decode(enc)
            iv = enc[:self.bs]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(enc[self.bs:]), self.bs)

    class __MAC:
        def __init__(self, key: str, data: str):
            self.__key = key
            self.__data = data

        def MAC(self):
            data = (self.__key + self.__data).encode()
            hash_object = hashlib.sha256(data)
            hex_dig = hash_object.hexdigest()
            return hex_dig

        def IfMac(self, mac: str):
            if mac == self.MAC():
                return True
            return False

    def __recv_enc_key(self, socket, private_key: int):
        recv = json.loads(self.recv(socket).decode())
        if recv['type'] == 'enc key':
            ssk = self.__DH.SharedSecretKey(recv['data']['publicKey'], private_key, recv['data']['pg'][0])
            return ssk, recv

    def __send_enc_key(self, socket, pg: tuple, private_key: int):
        public_key = self.__DH.PublicKey(pg[1], private_key, pg[0])
        message = self.message('enc key', {'pg': pg, 'publicKey': public_key})
        self.send(socket, message)

    def GenPG(self):
        p = number.getPrime(self.byte)
        g = pow(2, 1, p)
        self.pg = p, g

    def enc_key(self, socket, count: int, prompter: str = 'server'):
        if count < 2:
            raise ValueError(f"The number of keys must be 2 or higher, and you have passed {count} "
                             f"to the 'count' parameter.")
        elif count >= 2:
            shared_secret_keys = set()
            for n in range(count):
                private_key = getrandbits(self.byte)
                if prompter == 'client':
                    ssk, recv = self.__recv_enc_key(socket, private_key)
                    shared_secret_keys.add(ssk)

                    self.__send_enc_key(socket, recv['data']['pg'], private_key)
                elif prompter == 'server':
                    self.__send_enc_key(socket, self.pg, private_key)

                    ssk, _ = self.__recv_enc_key(socket, private_key)
                    shared_secret_keys.add(ssk)
                else:
                    raise ValueError(f'The value of the "prompter" parameter is incorrect, it should be '
                                     f'"server" or "client", and you specified "{prompter}".')

            return shared_secret_keys

    def __encSend(self, key: str, mac_key: str, message: str):
        aes = self.__AESCipher(key)
        enc_message = aes.Encrypt(message).decode()

        mac = self.__MAC(mac_key, enc_message)
        message = self.message('message', {'message': enc_message, 'mac': mac.MAC()})
        return message

    def encSend(self, socket, message_key: str, mac_key: str, message: str):
        message = self.__encSend(message_key, mac_key, message)
        self.send(socket, message)

    def __encRecv(self, recv: dict, key: str, mac_key: str):
        if recv['type'] == 'message':
            data = recv['data']
            mac = self.__MAC(mac_key, data['message'])
            if mac.IfMac(data['mac']):
                aes = self.__AESCipher(key)
                message = aes.Decrypt(data['message'].encode('utf-8'))
                data['message'] = message.decode('utf-8')
                data.pop('mac')
                recv['data'] = data
            else:
                return self.message('error', 'MAC does not match')
            return recv

    def encRecv(self, socket, message_key: str, mac_key: str):
        recv = json.loads(self.recv(socket).decode('utf-8'))
        return self.__encRecv(recv, message_key, mac_key)

    async def encSendAsync(self, loop: asyncio.get_event_loop or asyncio.set_event_loop, socket,
                           message_key: str, mac_key: str, message: str):
        message = self.__encSend(message_key, mac_key, message)
        await self.ASY_DTP(loop).send(socket, message)

    async def encRecvAsync(self, loop: asyncio.get_event_loop, socket, message_key: str, mac_key: str):
        recv = await self.ASY_DTP(loop).recv(socket)
        if recv:
            recv = json.loads(recv.decode('utf-8'))
            return self.__encRecv(recv, message_key, mac_key)