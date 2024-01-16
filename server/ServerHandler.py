import base64
import datetime
import os
import json
import time
from threading import Thread
import socket
from commons import PersistentStorage
from commons import RsaCommons
from commons import SocketCommons
from commons.Logger import Logger, LogType
from server.Authentication import Authentication
from server import ServiceHandlers
from commons.Utils import Bcolors


# Public client key is not binding generated new each time.
class _ActiveSession(Thread):
    client_ip: str
    client_port: int
    _conn: socket.socket
    _public_private_server_keys: RsaCommons.PublicPrivateKeyWrapper

    def __init__(self, ip, port, conn, public_private_server_keys: RsaCommons.PublicPrivateKeyWrapper):
        self.client_ip = ip
        self.client_port = port
        self._notSafeConnection = conn
        self._public_private_server_keys = public_private_server_keys
        super(_ActiveSession, self).__init__()

    # either signed by client unknown_server_data is correct or authorization code
    # also it should return symmetric connection
    def authenticatesession(self, safe_connection: SocketCommons.SafeConnection) -> (bool, SocketCommons.SafeConnection):
        verification = bytes(datetime.date.today().strftime("%d/%m/%Y %H:%M:%S"), "utf-8") + b"," + base64.b64encode(os.urandom(16))
        signature = self._public_private_server_keys.sign(verification)

        to_send = base64.b64encode(bytes(json.dumps({"verification": str(base64.b64encode(verification), 'utf-8'), "signature": str(base64.b64encode(signature), 'utf-8')}), 'utf-8')) + b'\n' + b'END'

        if(not safe_connection.sendencrypted(to_send)):
            safe_connection.closeconnection()
            Logger.log("Couldn't send auth data to {}:{}".format(self.client_ip, self.client_port), LogType.INFO)
            return True, None

        what_action = safe_connection.allpacketstoend()
        if(len(what_action) != 3):
            Logger.log("Client {}:{} dropped connection at authentication, incorrect amount of auth data".format(self.client_ip, self.client_port), LogType.INFO)
            safe_connection.closeconnection()
            return True, None

        try:
            from_client_data = json.loads(base64.b64decode(what_action[1]))
        except Exception:
            Logger.log("Failed to parse data from client, is that tampering?", LogType.WARNING)
            safe_connection.closeconnection()
            return True, None

        if ('public_key' not in from_client_data or 'data' not in from_client_data or 'signature' not in from_client_data):
            Logger.log("Client {}:{} send missing unknown_server_data is that an attack?".format(self.client_ip, self.client_port), LogType.WARNING)
            safe_connection.closeconnection()
            return True, None

        try:
            authenticated_client_public_key = RsaCommons.EncryptOnlyPublic.frombytes(base64.b64decode(bytes(from_client_data['public_key'], 'utf-8')))
        except Exception:
            Logger.log("Failed to parse data from client {}:{}, is that tampering?".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
            safe_connection.closeconnection()
            return True, None

        if (not authenticated_client_public_key.verifysignature(bytes(from_client_data['data'], 'utf-8'), base64.b64decode(bytes(from_client_data['signature'], 'utf-8')))):
            Logger.log("Client {}:{} send signature that cannot be confirmed.".format(self.client_ip, self.client_port), LogType.SEVERE)
            safe_connection.closeconnection()
            return True, None

        try:
            data = json.loads(base64.b64decode(from_client_data['data']))
        except Exception:
            Logger.log("Failed to parse data from client {}:{}, is that tampering?".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
            safe_connection.closeconnection()
            return True, None

        if ('verification' not in data):
            Logger.log("Client {}:{} send missing unknown_server_data is that an attack?".format(self.client_ip, self.client_port), LogType.WARNING)
            safe_connection.closeconnection()
            return True, None
        try:
            verification_client_side = bytes(base64.b64decode(data['verification']))
        except Exception:
            Logger.log("Failed to parse data from client {}:{}, is that tampering?".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
            return True, None

        if (verification_client_side != verification):
            Logger.log("Server verification unknown_server_data doesn't match for client {}:{}".format(self.client_ip, self.client_port), LogType.SEVERE)
            safe_connection.closeconnection()
            return True, None

        if what_action[0] not in [SocketCommons.ValidActions.registercode.value, SocketCommons.ValidActions.initpub.value]:
            Logger.log("Client {}:{} was tampering with data".format(self.client_ip, self.client_port), LogType.SEVERE)
            safe_connection.closeconnection()
            return True, None

        if(what_action[0] == SocketCommons.ValidActions.registercode.value):
            if ('code' not in data):
                Logger.log("Client {}:{} send missing data is that an attack?".format(self.client_ip, self.client_port), LogType.WARNING)
                safe_connection.closeconnection()
                return True, None

            # i dont care this counts as tampering
            if(type(data['code']) != int):
                Logger.log("Client {}:{} was tampering with data".format(self.client_ip, self.client_port), LogType.SEVERE)
                safe_connection.closeconnection()
                return True, None

            success, logstr, logtype = Authentication.authenticate(data['code'], base64.b64decode(bytes(from_client_data['public_key'], 'utf-8')))

            if (not success):
                Logger.log(logstr.format(self.client_ip, self.client_port), logtype)
                safe_connection.closeconnection()
                return True, None

        if(what_action[0] == SocketCommons.ValidActions.initpub.value):
            success = Authentication.authenticatepubliccertificate(base64.b64decode(bytes(from_client_data['public_key'], 'utf-8')))
            if(not success):
                Logger.log("Client {}:{} tried to authenticate using certificate however it did not end well.".format(self.client_ip, self.client_port), LogType.WARNING)
                safe_connection.closeconnection()
                return True, None

        SocketCommons.ConnectionManager.connections[safe_connection.getnotsafeconnection().conninfo()]['isauthenticated'] = True
        SocketCommons.ConnectionManager.connections[safe_connection.getnotsafeconnection().conninfo()]['authorizepublickey'] = RsaCommons.EncryptOnlyPublic.frombytes(base64.b64decode(bytes(from_client_data['public_key'], 'utf-8')))
        symmetric = RsaCommons.SymmetricEncryption.generate(32)

        to_send = base64.b64encode(symmetric.getkey(True)) + b"\n" + b"END"

        safe_connection.sendencrypted(to_send)

        # Client side does this at the same time or there will be problem.
        safe_connection.setnewencinterface(symmetric)
        return False, safe_connection

    def initialhandshake(self)->(bool, SocketCommons.SafeConnection):
        if((self.client_ip, self.client_port) in SocketCommons.ConnectionManager.connections):
            Logger.log("Client {}:{} is trying to connect. Even the _notSafeConnection is estabilished already. Is this an attack?".format(self.client_ip, self.client_port), LogType.SEVERE)
            return True, None

        not_safe_connection = SocketCommons.NotSafeConnection(self.client_ip, self.client_port, self._notSafeConnection)

        if(not not_safe_connection.send(self._public_private_server_keys.exportpublicpem())):
            Logger.log("Client {}:{} disconnected.".format(self.client_ip, self.client_port), LogType.INFO)
            self._notSafeConnection.close()
            return True, None

        client_session_public = b''
        while True:
            if (b'-----END PUBLIC KEY-----' in client_session_public):
                break
            response = not_safe_connection.recv(self._public_private_server_keys.getrecvsize())
            if (response):
                Logger.log("Connection for {}:{} failed while exchanging session keys".format(self.client_ip, self.client_port), LogType.WARNING)
                return True, None
            decrypted_response = self._public_private_server_keys.decrypt(response.getdata())
            if(decrypted_response):
                Logger.log("Client {}:{} send weird udata, error while decrypting is that an attack?".format(self.client_ip, self.client_port), LogType.WARNING)
                return True, None
            client_session_public = client_session_public + decrypted_response.getdata()

        client_session_key: RsaCommons.EncryptOnlyPublic = RsaCommons.EncryptOnlyPublic.frombytes(client_session_public)
        encryption_interface = RsaCommons.BothSidesWrapped.frombytes(self._public_private_server_keys.exportprivatepem(True), self._public_private_server_keys.exportpublicpem(), client_session_key)
        return False, SocketCommons.SafeConnection(not_safe_connection, encryption_interface)

    def run(self):
        failed, initial_safe_connection = self.initialhandshake()
        if(failed):
            return

        failed, symmetric_connection = self.authenticatesession(initial_safe_connection)
        if(failed):
            return

        symmetric_connection: SocketCommons.SafeConnection
        ServiceHandlers.eachthreadcallsthat(symmetric_connection, self._public_private_server_keys)


class _JustListener(Thread):
    _public_private_server_keys: RsaCommons.PublicPrivateKeyWrapper = None
    _tcp_sock: socket.socket

    def __init__(self, tcp_sock, public_private_server_keys: RsaCommons.PublicPrivateKeyWrapper):
        self._public_private_server_keys = public_private_server_keys
        self._tcp_sock = tcp_sock
        super(_JustListener, self).__init__()

    def run(self) -> None:
        while True:
            self._tcp_sock.listen(30)
            # I want to have pairing process there and then when client is connected to push it to async.
            (connection, (client_ip, client_port)) = self._tcp_sock.accept()
            # TLDR is that, without timeout i stops on recv, and beacuse its python i didnt find any non messy way to kill thread.
            # Please look at notsafeconnection and how it's handled there
            connection.settimeout(100)
            Logger.log("Client {}:{} is trying to connect. Starting thread will be handled asynchronously".format(client_ip, client_port), LogType.INFO)
            _ActiveSession(client_ip, client_port, connection, self._public_private_server_keys).start()


class ServerHandleClass:
    def __init__(self, data: PersistentStorage.PersistentStore):
        while True:
            try:
                # Last step uses tqdm and it likes to break console view.
                # The only reason sleep is there
                time.sleep(1)
                listen_server_ip = input("Please type IP on which server should listen: ")
                listen_port = int(input("Please type port on which server will listen: "))

                tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp_sock.bind((listen_server_ip, listen_port))

                self.__ServerListener = _JustListener(tcp_sock, data.getstoredwrapper())
                self.__ServerListener.start()
                break
            except Exception:
                print(Bcolors.WARNING + "Unfourtunately ip or port you provided cannot be binded. Please try again" + Bcolors.ENDC)
