import base64
import os
import Crypto
import cryptography.fernet
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Util import number
from Crypto.Hash import SHA512


# I didn't want to use try catches this feels better.
# Also its basically same class from socketCommons
class DecryptionResponse:
    _failed = None
    _status_check = None
    _data = None

    def __init__(self, failed: bool, data: bytes = None):
        self._failed = failed
        self._data = data

    def __bool__(self):
        self._status_check = True
        return self._failed

    def getdata(self):
        if(not self._status_check):
            raise Exception("You didn't check if DecryptionResponse got handled properly.")
        return self._data


# Template class symmetric,asymmetric
class EncryptionInterface:
    def encrypt(self, data: bytes) -> bytes:
        """Just a reference"""
        raise Exception("Invalid inherence")
        pass

#   #Should be checked with try catch, but should return Decryption Response do not return error.
    def decrypt(self, ciphertext: bytes) -> DecryptionResponse:
        """Just a reference"""
        raise Exception("Invalid inherence")
        pass

    def recvsize(self) -> int:
        """Just a reference"""
        raise Exception("Invalid inherence")
        pass

    def sendsize(self):
        raise Exception("Invalid inherence")
        pass

    def connectiontype(self) -> str:
        """Just a reference"""
        raise Exception("Invalid inherence")
        pass


class SymmetricEncryption(EncryptionInterface):

    _key: bytes = None
    _fernet: cryptography.fernet.Fernet = None
    _packet_size_bytes = None
    _data_size: int = None

    # data_size from this packetsize is being calculated
    def __init__(self, key: bytes, data_size: int = 8096):
        self._key = key
        self._fernet = cryptography.fernet.Fernet(key)
        self._data_size = data_size
        self._packet_size_bytes = len(self._fernet.encrypt(os.urandom(self._data_size)))

    def encrypt(self, data: bytes) -> bytes:
        if(len(data) > self._data_size):
            raise Exception("Expected less unknown_server_data. This is fatal issue problem with encryption")

        encrypted = self._fernet.encrypt(data)
        return encrypted

    def decrypt(self, ciphertext: bytes) -> DecryptionResponse:
        if(len(ciphertext) > self._packet_size_bytes):
            raise Exception("Expected less unknown_server_data. This is fatal issue problem with decryption")
        try:
            return DecryptionResponse(False, self._fernet.decrypt(ciphertext))
        except Exception:
            # I dont want to put this in logger
            return DecryptionResponse(True)

    def recvsize(self) -> int:
        return self._packet_size_bytes

    def sendsize(self):
        return self._data_size

    def getkey(self, confirm: bool):
        if(confirm):
            return self._key
        raise Exception("Wanted to get symmetric key without confirmation")

    def connectiontype(self) -> str:
        return "Symmetric, keysize {}".format(len(self._key))

    @classmethod
    def generate(cls, key_size_bytes: int):
        if(key_size_bytes < 32):
            raise Exception("Symmetric key must be at least 32 bytes")

        _key = base64.urlsafe_b64encode(os.urandom(key_size_bytes))
        return cls(_key)


# Make sure to not send more bytes of unknown_server_data than the key.
class PublicKeyDataSafety():
    _block_size: int = None
    # I want to receive X amount of block size, for now i settled on 8.
    _recv_size: int = None
    _actual_data_in_packet: int = None
    _pub_cip: Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher = None

    def __init__(self, public_key_rsa: Crypto.PublicKey.RSA.RsaKey):
        self._pub_cip = PKCS1_OAEP.new(public_key_rsa)
        # IDE says its unresolved but it's probably just wrong type
        # TLDR it's working
        size_in_bits = number.size(self._pub_cip._key.n)

        self._block_size = number.ceil_div(size_in_bits, 8)
        self._recv_size = self._block_size * 8
        # Same as above IDE doesn't resolve its working
        hash_digest_size = self._pub_cip._hashObj.digest_size
        self._actual_data_in_packet = self._block_size - 2 * hash_digest_size - 2

    def getblocksize(self):
        return self._block_size

    def getrecvsize(self):
        return self._recv_size

    def getamntofdatainpacket(self):
        return self._actual_data_in_packet


# Using this class implies we have public key from sender. We can only encrypt unknown_server_data
class EncryptOnlyPublic(PublicKeyDataSafety):
    _public_key: Crypto.PublicKey.RSA.RsaKey = None

    def __init__(self, public_key: Crypto.PublicKey.RSA.RsaKey):
        self._public_key = public_key
        super().__init__(public_key)

    @classmethod
    def frombytes(cls, public_key: bytes):
        return cls(RSA.importKey(public_key))

    def encrypt(self, data: bytes) -> bytes:
        encrypted = []
        for limit in range(0, len(data), self.getamntofdatainpacket()):
            encrypted.append(self._pub_cip.encrypt(data[limit: limit + self.getamntofdatainpacket()]))
        cipher_text = b"".join(encrypted)
        return cipher_text

    def verifysignature(self, data, what_signature: bytes) -> bool:
        checker = PKCS1_v1_5.new(self._public_key)

        if(isinstance(data, SHA512.SHA512Hash)):
            return checker.verify(data, what_signature)

        return checker.verify(SHA512.new(data), what_signature)

    def getencryptiononlypublickey(self) -> bytes:
        return self._public_key.export_key()


class PublicPrivateKeyWrapper(PublicKeyDataSafety):
    _private_key = None
    _public_key = None
    _private_ciph = None

    def __init__(self, private_key: Crypto.PublicKey.RSA.RsaKey, public_key_rsa: Crypto.PublicKey.RSA.RsaKey):
        self._public_key = public_key_rsa
        self._private_key = private_key
        self._private_ciph = PKCS1_OAEP.new(self._private_key)
        super().__init__(public_key_rsa)

    def decrypt(self, cipher_text: bytes) -> DecryptionResponse:
        try:
            resultant_text = []
            for index in range(0, len(cipher_text), self.getblocksize()):
                decrypted_block = self._private_ciph.decrypt(
                    cipher_text[index: index + self.getblocksize()])
                resultant_text.append(decrypted_block)
            plain_text = b''.join(resultant_text)
            return DecryptionResponse(False, plain_text)
        except Exception:
            # I don't want to put this in logger
            return DecryptionResponse(True)

    def exportpublicpem(self) -> bytes:
        return self._public_key.exportKey("PEM")

    def exportprivatepem(self, confirm: bool) -> bytes:
        if (confirm):
            return self._private_key.exportKey("PEM")
        raise Exception("Wanted to export private key without confirmation")

    def sign(self, what) -> bytes:
        signer = PKCS1_v1_5.new(self._private_key)
        if(isinstance(what, SHA512.SHA512Hash)):
            return signer.sign(what)

        sha_sum = SHA512.new(what)
        return signer.sign(sha_sum)

    def connectiontype(self) -> str:
        return "Asymmetric, key-size {}".format(self.getblocksize() * 8)

    @classmethod
    def frombytes(cls, private_key: bytes, public_key: bytes):
        private_key = RSA.import_key(private_key)
        public_key = RSA.importKey(public_key)
        return cls(private_key, public_key)

    @classmethod
    def generate(cls, key_size: int):
        private_key = RSA.generate(key_size*8, Random.new().read)
        public_key = private_key.public_key()
        return cls(private_key, public_key)


# Both sides wrapped beacuse the actual encrypt bit uses key from another host.
class BothSidesWrapped(PublicPrivateKeyWrapper, EncryptionInterface):
    _client_public_only: EncryptOnlyPublic = None

    def __init__(self, private_key: Crypto.PublicKey.RSA.RsaKey, public_key_rsa: Crypto.PublicKey.RSA.RsaKey, client_public_key):
        self._client_public_only = client_public_key
        super().__init__(private_key, public_key_rsa)

    # We need to use another key
    def encrypt(self, data: bytes) -> bytes:
        return self._client_public_only.encrypt(data)

    @classmethod
    def frombytes(cls, private_key: bytes, public_key: bytes, client_public_key):
        private_key = RSA.import_key(private_key)
        public_key = RSA.import_key(public_key)
        return cls(private_key, public_key, client_public_key)

    @classmethod
    def generate(cls, client_public: EncryptOnlyPublic):
        # With that we should be just matching server key size. Also user might not know what good value would be so calculating size from server key seems resonable
        private_key = RSA.generate(client_public.getblocksize() * 8, Random.new().read)
        public_key = private_key.public_key()
        return cls(private_key, public_key, client_public)

    def sendsize(self):
        return super().getrecvsize()

    def recvsize(self) -> int:
        return super().getrecvsize()
