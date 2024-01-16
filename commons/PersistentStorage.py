import base64
import os.path
import os
import pickle
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from commons import Utils
from commons import RsaCommons


# This could be handled better.
class PersistentStore:
    _data = dict()
    _fernet = None

    # it will store either client or server.
    _impl = None

    def initializefernet(self, password: bytes, salt: bytes):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, iterations=480000,
                         salt=salt)
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self._fernet = Fernet(key)

    def save(self):
        pickled = pickle.dumps(self._data)
        to_close = open(self._dbFile, "wb")
        to_write = pickle.dumps({'salt': self._salt, 'data': self._fernet.encrypt(pickled)})
        to_close.write(to_write)
        to_close.flush()
        to_close.close()

    _called = []

    def getorcreatedata(self, what: str, is_dict=False):
        if(what in self._called):
            raise Utils.FatalError("This data was already called, Not recoverable issue")
        self._called.append(what)
        if(what in self._data):
            return self._data[what]
        if(is_dict):
            self._data[what] = {}
            return self._data[what]
        else:
            self._data[what] = []
            return self._data[what]

    def __init__(self, impl):
        self._dbFile = impl + ".encrypted"
        password_input = bytes(input("Please type your password: "), "utf-8")

        if(os.path.exists(self._dbFile)):
            notdecryptedfile = open(self._dbFile, "rb")
            contains_salt = pickle.load(notdecryptedfile)
            self._salt = contains_salt['salt']

            notdecryptedfile.close()
            self.initializefernet(password_input, self._salt)

            try:
                decrypted_butpickled = self._fernet.decrypt(contains_salt['data'])
            except Exception:
                raise Utils.FatalError("Password you have provided is incorrect please try again")

            self._data = pickle.loads(decrypted_butpickled)
            print("Successfully read file your public key is")
            print(Utils.Bcolors.TURQOISEBACKGROUNDBLACK + str(self._data["public"], "utf-8") + "\n" + Utils.Bcolors.ENDC)
            return

        # Anything below it wasn't initalized before
        password_confirm = bytes(input(f"""It looks like you are running program for first time. Type your password again to generate new {impl}.encrypted file or make sure it's in directory where python is being ran from. (Press Q to quit) """), "utf-8")
        if(password_confirm.lower() == "q"):
            raise Utils.UserWantShutdown
        if(password_confirm != password_input):
            raise Utils.FatalError("Passwords do not match, please try again")

        self._salt = os.urandom(32)
        self.initializefernet(password_input, self._salt)

        print("Initializing public/private keys")

        wrapped = RsaCommons.PublicPrivateKeyWrapper.generate(256)

        print("Generated keys, I am giving you your public key.")
        self._data.update({"public": wrapped.exportpublicpem(), "private": wrapped.exportprivatepem(True)})
        print(Utils.Bcolors.TURQOISEBACKGROUNDBLACK + str(self._data["public"], "utf-8") + "\n" + Utils.Bcolors.ENDC)

        print("Please don't shutdown. Save file is being created")
        self.save()
        return

    def getstoredwrapper(self)->RsaCommons.PublicPrivateKeyWrapper:
        return RsaCommons.PublicPrivateKeyWrapper.frombytes(self._data["private"], self._data["public"])


