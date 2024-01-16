import base64
import json
import time
from commons import RsaCommons
from commons import SocketCommons
from commons import Utils
from commons.Logger import Logger, LogType
from Crypto.Hash import MD5
from commons.Utils import Bcolors


class ClientHandlerClass:
    _server_ip: str
    _server_port: int

    # more for internal use.
    _notsafe_conn: SocketCommons.NotSafeConnection
    _server_public_key: RsaCommons.EncryptOnlyPublic
    _safe_connection: SocketCommons.SafeConnection

    def serverpublickey(self) -> RsaCommons.EncryptOnlyPublic:
        return self._server_public_key
    def initialhandshake(self):
        notsafe_conn = None
        while notsafe_conn is None:
            ip = input("Please insert ip address that you want to connect to: ")
            port = input("Please insert port number: ")
            try:
                notsafe_conn = SocketCommons.NotSafeConnection.connecttoserver(ip, int(port))
            except Exception:
                print(Bcolors.WARNING + "Unfortunately you've made a mistake in a port or address try again." + Bcolors.ENDC)
                continue

        server_public_key_bytes = b''
        while True:
            if (b'-----END PUBLIC KEY-----' in server_public_key_bytes):
                break
            server_response = notsafe_conn.recv(256)
            if(server_response):
                Logger.log("Connection to server failed. Unable to complete handshake", LogType.SEVERE)
                return True, None
            server_public_key_bytes = server_public_key_bytes + server_response.getdata()

        print("This is public key of a server that you want to connect to, make sure it's correct: " + "\n" + str(server_public_key_bytes, "utf-8"))
        while True:
            ans = input("Please confirm validity of a server (yes/no): ")
            if(ans.lower() == "yes"):
                break
            if(ans.lower() == "no"):
                raise Utils.FatalError("Client tried to connect but user decided that public key is incorrect")
            if(ans.lower() == "maybe"):
                print("This is easter egg, does nothing, wondering if someone will see it")
                continue

        self._server_public_key = RsaCommons.EncryptOnlyPublic.frombytes(server_public_key_bytes)
        both_sides_wrapped = RsaCommons.BothSidesWrapped.generate(self._server_public_key)

        if(not notsafe_conn.send(self._server_public_key.encrypt(both_sides_wrapped.exportpublicpem()))):
            Logger.log("Tried to send public key but it failed", LogType.WARNING)
            return True, None

        secure_conn_hand_shake_only = SocketCommons.SafeConnection(notsafe_conn, both_sides_wrapped)
        return False, secure_conn_hand_shake_only

    def getunknowndata(self, secure_conn_hand_shake_only: SocketCommons.SafeConnection):
        server_unknown_data = secure_conn_hand_shake_only.allpacketstoend()

        if(len(server_unknown_data) != 2):
            Logger.log("Server send incorrect amount of Data", LogType.SEVERE)
            secure_conn_hand_shake_only.closeconnection()
            return True, None

        try:
            data: {} = json.loads(base64.b64decode(server_unknown_data[0]))
        except Exception:
            raise Utils.FatalError("Server data cannot be parsed")

        if('verification' not in data or 'signature' not in data):
            Logger.log("Server send incorrect signed data, cannot authenticate", LogType.SEVERE)
            secure_conn_hand_shake_only.closeconnection()
            return True, None

        # convert to bytes
        try:
            data['verification'] = base64.b64decode(bytes(data['verification'], 'utf-8'))
            data['signature'] = base64.b64decode(bytes(data['signature'], 'utf-8'))
        except Exception:
            raise Utils.FatalError("Server data cannot be parsed")

        if(not self._server_public_key.verifysignature(data['verification'], data['signature'])):
            Logger.log("Could not verify servers signature this is really big issue. Please contact with administrator", LogType.SEVERE)
            secure_conn_hand_shake_only.closeconnection()
            return True, None
        return False, data

    def performauthandsign(self, unknown_server_data, persistent_dict, persistent_data, secure_conn_hand_shake_only: SocketCommons.SafeConnection):
        # check if it was lastly connected
        if('lastConnected' not in persistent_dict):
            code = input("Please type code that is provided in server to verify your identity.")
            # Look, its numbers code on server if someone does that it's deserved
            if(not code.isdigit()):
                time.sleep(999999)
                raise Exception("You've been trolled exception")

            sendto_srv = base64.b64encode(bytes(json.dumps({"verification": str(base64.b64encode(unknown_server_data['verification']), 'utf-8'), "code": int(code)}), 'utf-8'))

            wrapped = persistent_data.getstoredwrapper()
            # Server needs to know which public key is using for auth and which is for session only. Signature is important
            sign_it = base64.b64encode(bytes(json.dumps({'signature': base64.b64encode(wrapped.sign(sendto_srv)).decode("utf-8"), 'data': sendto_srv.decode("utf-8"), 'public_key': base64.b64encode(wrapped.exportpublicpem()).decode("utf-8")}), "utf-8"))
            to_send = SocketCommons.ValidActions.registercode.value + b"\n" + sign_it + b"\n" + b"END"
            if(not secure_conn_hand_shake_only.sendencrypted(to_send)):
                Logger.log("Could not send unknown server data to server", LogType.SEVERE)
                secure_conn_hand_shake_only.closeconnection()
                return True
            return False
        if (persistent_dict['lastConnected'] != self._server_public_key.getencryptiononlypublickey()):
            # https://stackoverflow.com/questions/6682815/deriving-an-ssh-fingerprint-from-a-public-key-in-python
            # also it doesnt matter if its correct, the md5 bit, it definitely checks for key validity i calculate something incorrect
            # wanted to see this error so much, brings me joy
            key = str(self._server_public_key.getencryptiononlypublickey(), "utf-8").strip().split()[1].encode('ascii')
            fp_plain = MD5.new(key).hexdigest()
            to_insert = ':'.join(a + b for a, b in zip(fp_plain[::2], fp_plain[1::2]))
            raise Utils.FatalError(f"""
                    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                    @     WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!    @
                    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                    IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
                    Someone could be eavesdropping on you right now (man-in-the-middle attack)!
                    It is also possible that the RSA host key has just been changed.
                    The fingerprint for the RSA key sent by the remote host is
                    {to_insert}.
                    Please contact your system administrator.
                    If this is correct, please delete your .encrypted file. And generate new identity.
                    """)

        sendto_srv = base64.b64encode(bytes(json.dumps({"verification": str(base64.b64encode(unknown_server_data['verification']), 'utf-8')}), 'utf-8'))
        wrapped = persistent_data.getstoredwrapper()
        # Session key is different from our saved keys, server doesnt know that this key yet exist that's why it's being send
        sign_it = base64.b64encode(bytes(json.dumps({'signature': base64.b64encode(wrapped.sign(sendto_srv)).decode("utf-8"), 'data': sendto_srv.decode("utf-8"), 'public_key': base64.b64encode(wrapped.exportpublicpem()).decode("utf-8")}), "utf-8"))
        to_send = SocketCommons.ValidActions.initpub.value + b"\n" + sign_it + b"\n" + b"END"

        if (not secure_conn_hand_shake_only.sendencrypted(to_send)):
            Logger.log("Could not send unknown server data to server", LogType.SEVERE)
            return True
        return False

    def receivesymmetrickey(self, secure_conn_hand_shake_only: SocketCommons.SafeConnection, persistent_dict):
        server_response = secure_conn_hand_shake_only.allpacketstoend()
        if(len(server_response) != 2):
            Logger.log("Client send wrong data for symmetric key.", LogType.SEVERE)
            return True, None
        persistent_dict['lastConnected'] = self._server_public_key.getencryptiononlypublickey()
        try:
            symmetric = RsaCommons.SymmetricEncryption(base64.b64decode(server_response[0]))
        except Exception:
            raise Utils.FatalError("Could not decode symmetric key from server")
        secure_conn_hand_shake_only.setnewencinterface(symmetric)
        return False, secure_conn_hand_shake_only

    def getsafeconnection(self) -> SocketCommons.SafeConnection:
        return self._safe_connection

    def __init__(self, persistent_dict, persistent_data):
        failed, secure_hand_shake_only = self.initialhandshake()
        if(failed):
            Logger.printlog(10)
            raise Utils.FatalError("Please see logs an error has occurred")

        failed, unknown_data = self.getunknowndata(secure_hand_shake_only)
        if(failed):
            Logger.printlog(10)
            raise Utils.FatalError("Please see logs an error has occurred")
        if(self.performauthandsign(unknown_data, persistent_dict, persistent_data, secure_hand_shake_only)):
            Logger.printlog(10)
            raise Utils.FatalError("Please see logs an error has occurred")
        failed, safe_conn = self.receivesymmetrickey(secure_hand_shake_only, persistent_dict)
        if(failed):
            Logger.printlog(10)
            raise Utils.FatalError("Please see logs an error has occurred")
        persistent_data.save()
        self._safe_connection = safe_conn
        Logger.log("Established safe connection with server", LogType.INFO)
