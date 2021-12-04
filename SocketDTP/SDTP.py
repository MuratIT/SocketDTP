import json
import base64
import hashlib
from DTP import DTP
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import number
from Crypto.Random.random import getrandbits


class SDTP(DTP):
    def __init__(self, pg: tuple = (0, 0), n: int = 1024):
        self.pg = pg
        self.n = n

    class __DH:
        @staticmethod
        def PublicKey(pg: tuple, privateKey):
            return pow(pg[1], privateKey, pg[0])

        @staticmethod
        def SharedSecretKey(PublicKey, privateKey, pg):
            return pow(PublicKey, privateKey, pg[0])

    class __AESCipher:
        def __init__(self, key):
            self.bs = AES.block_size
            self.key = hashlib.sha256(key.encode()).digest()

        @staticmethod
        def _unpad(s):
            return s[:-ord(s[len(s) - 1:])]

        def encrypt(self, raw):
            raw = self._pad(raw)
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return base64.b64encode(iv + cipher.encrypt(raw.encode()))

        def decrypt(self, enc):
            enc = base64.b64decode(enc)
            iv = enc[:AES.block_size]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

        def _pad(self, s):
            return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    class __MAC:
        def __init__(self, key, data):
            self.__key = key
            self.__data = data

        def MAC(self):
            data = (str(self.__key) + str(self.__data)).encode()
            hash_object = hashlib.sha256(data)
            hex_dig = hash_object.hexdigest()
            return hex_dig

        def ifMAC(self, mac):
            if mac == self.MAC():
                return True
            return False

    def GenPG(self):
        p = number.getPrime(self.n)
        g = pow(2, 1, p)
        self.pg = p, g

    def enc_key_server(self, connect, count: int):
        arr = set()

        for i in range(count):
            private_key = getrandbits(self.n)
            public_key = self.__DH.PublicKey(self.pg, private_key)
            message = self.message('enc_key', {'pg': self.pg, 'publicKey': public_key})
            self.send(connect, message)

            recv = json.loads(self.recv(connect).decode())
            if recv['type'] == 'enc_key':
                key = self.__DH.SharedSecretKey(recv['data']['publicKey'], private_key, self.pg)
                arr.add(key)

        return arr

    def enc_key_client(self, socket, count: int):
        arr = set()

        for i in range(count):
            recv = json.loads(self.recv(socket).decode())
            if recv['type'] == 'enc_key':
                private_key = getrandbits(self.n)
                ssk = self.__DH.SharedSecretKey(recv['data']['publicKey'], private_key, recv['data']['pg'])
                arr.add(ssk)

                pub_key = self.__DH.PublicKey(recv['data']['pg'], private_key)
                message = self.message('enc_key', {'publicKey': pub_key})
                self.send(socket, message)

        return arr

    def __encSend(self, key, mac_key, message):
        aes = self.__AESCipher(key)
        enc_message = aes.encrypt(message).decode()
        mac = self.__MAC(mac_key, enc_message)
        message = self.message('message', {'message': enc_message, 'mac': mac.MAC()})
        return message

    def encSend(self, socket, key, mac_key, message):
        message = self.__encSend(key, mac_key, message)
        self.send(socket, message)

    def __encRecv(self, recv, key, mac_key):
        if recv['type'] == 'message':
            data = recv['data']
            mac = self.__MAC(mac_key, data['message'])
            if mac.ifMAC(data['mac']):
                aes = self.__AESCipher(key)
                message = aes.decrypt(data['message'].encode())
                data['message'] = message
                data.pop('mac')
                recv['data'] = data
            else:
                return self.message('error', 'mac is not good')
            return recv

    def encRecv(self, socket, key, mac_key):
        recv = json.loads(self.recv(socket))
        return self.__encRecv(recv, key, mac_key)

    async def encSendAsync(self, loop, socket, key, mac_key, message):
        message = self.__encSend(key, mac_key, message)
        await self.ASY_DTP(loop).send(socket, message)

    async def encRecvAsync(self, loop, socket, key, mac_key):
        recv = await self.ASY_DTP(loop).recv(socket)
        recv = json.loads(recv)
        return self.__encRecv(recv, key, mac_key)