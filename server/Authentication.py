from commons.Logger import LogType, Logger
from commons.Utils import Bcolors
import time
from random import randint
import tqdm


# static class, should not do anything else that yes,no
class Authentication:
    valid_public_certs = []
    key: int = None
    _success_public = b''
    _internal_verification = {}

    @staticmethod
    def addtrustedcert(cert: bytes):
        Authentication.valid_public_certs.append(cert)

    @staticmethod
    def _load(data):
        Authentication.valid_public_certs = data

    # I wont make another class just for Response on this doesn't make sense. Already too much boilerplate code
    @staticmethod
    def authenticate(code: int, public_key: bytes) -> (bool, str, LogType):
        if(Authentication.key is None):
            return False, "{}:{} tried to authenticate, even key is not generated is that an attack?", LogType.SEVERE
        if(code == Authentication.key):
            Authentication.key = None
            Authentication._success_public = public_key

            while True:
                # it can wait forever for server to accept too bad
                if(public_key not in Authentication._internal_verification):
                    time.sleep(10)
                    continue

                if(Authentication._internal_verification[public_key]):
                    del Authentication._internal_verification[public_key]
                    return True, "{}:{} authenticated. Performing further _notSafeConnection.", LogType.INFO
                if(not Authentication._internal_verification[public_key]):
                    del Authentication._internal_verification[public_key]
                    return False, "{}:{} tried to authenticate, but failed, because server decided this public cert is not safe.", LogType.WARNING

        return False, "{}:{} tried to authenticate, but failed", LogType.WARNING

    @staticmethod
    def authenticatepubliccertificate(cert: bytes):
        return cert in Authentication.valid_public_certs

    @staticmethod
    def generatecode(howmuchtime: int = 60):
        if(Authentication.key != None):
            raise Exception("AH hell nah, this should be handled by main thread. Why it even has issue with this call")

        Logger.log("Server generates authentication code", LogType.WARNING)

        Authentication.key = randint(1000000, 9999999)
        print(f"""Your code is {Authentication.key}, your input is disabled for duration of authentication. After {howmuchtime} seconds code will expire""")
        # yes this is two lines
        print("\n")
        for i in tqdm.tqdm(range(howmuchtime), bar_format="[ time left: {remaining} ]"):
            if(Authentication._success_public != b''):
                # just to break quicker from the loop
                break
            time.sleep(1)

        if(Authentication._success_public != b''):
            print(Authentication._success_public)
            data = ""
            while data != "yes" or "no":
                data = input(Bcolors.WARNING + "Above publickey got sucessfully code. Are you sure that is someone trusted (yes/no)" + Bcolors.ENDC).lower()

                if(data == "yes"):
                    Logger.log("Server added new certificate to trusted DB", LogType.INFO)
                    Authentication._internal_verification[Authentication._success_public] = True
                    Authentication.addtrustedcert(Authentication._success_public)
                    Authentication._success_public = b''
                    return
                if(data == "no"):
                    Logger.log("key got generated. User determined that the key is not safe", LogType.SEVERE)
                    Authentication._internal_verification[Authentication._success_public] = False
                    Authentication._success_public = b''
                    return
        Authentication.key = None
        Logger.log("Generated code expired.", LogType.INFO)
        print("key expired please continue with your normal operations")
        return
