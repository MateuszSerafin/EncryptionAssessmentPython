from enum import Enum
from commons import RsaCommons
import socket
from commons.Logger import Logger, LogType


class ConnectionManager:
    connections = {}


class Response:
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
            raise Exception("You didn't check if connection got handled properly.")
        return self._data


class NotSafeConnection:
    _client_ip: str = None
    _client_port: int = None
    _connection = None
    _recv_lock: bool = False

    def __init__(self, client_ip, client_port, connection):
        self._client_ip = client_ip
        self._client_port = client_port
        self._connection = connection

    def terminateconnection(self):
        self._connection.close()

    def send(self, data: bytes) -> bool:
        try:
            self._connection.send(data)
            return True
        except Exception or socket.timeout as e:
            if (isinstance(e, socket.timeout)):
                return True
            return False

    def recv(self, how_much_bytes: int) -> Response:
        if(self._recv_lock):
            raise Exception("Only one thread can have instance of recv")
        self._recv_lock = True

        # Error - Process got killed something exploded
        # Normal break - Closed socket
        while True:
            try:
                data = self._connection.recv(how_much_bytes)
                if not data:
                    self._recv_lock = False
                    return Response(True)
                self._recv_lock = False
                return Response(False, data)
            except Exception or socket.timeout as e:
                # If timed out, continue,
                if(isinstance(e, socket.timeout)):
                    continue
                self._recv_lock = False
                return Response(True)

    def conninfo(self) -> (_client_ip, _client_port):
        return (self._client_ip, self._client_port)

    @classmethod
    def connecttoserver(cls, server_ip, server_port):
        _connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _connection.settimeout(100)
        _connection.connect((server_ip, server_port))
        return cls(server_ip, server_port, _connection)


class SafeConnection:
    _not_safe_connection: NotSafeConnection = None
    _enc_interface: RsaCommons.EncryptionInterface = None

    def __init__(self, not_safe_connection: NotSafeConnection, encryption_interface: RsaCommons.EncryptionInterface):
        self._not_safe_connection = not_safe_connection
        self._enc_interface = encryption_interface
        ConnectionManager.connections.update({self._not_safe_connection.conninfo(): {"instance": self, "isauthenticated": False}})

    def closeconnection(self):
        self._not_safe_connection.terminateconnection()
        if(self._not_safe_connection.conninfo() in ConnectionManager.connections):
            del ConnectionManager.connections[self._not_safe_connection.conninfo()]

    def sendencrypted(self, unencrypted: bytes) -> bool:
        for index in range(0, len(unencrypted), self._enc_interface.sendsize()):
            encrypted = self._enc_interface.encrypt(unencrypted[index:index+self._enc_interface.sendsize()])
            if(not self._not_safe_connection.send(len(encrypted).to_bytes(2, 'big') + b' ' + encrypted)):
                return False
        return True

    # Caller should be checking if end of unknown_server_data (chunky download)
    def listenonepacket(self):
        cipher_response = self._not_safe_connection.recv(self._enc_interface.recvsize())

        if(cipher_response):
            self.closeconnection()
            ip, port = self._not_safe_connection.conninfo()
            Logger.log("Connection {}:{} failed or was shutdown".format(ip, port), LogType.INFO)
            return Response(True)

        data_not_splited = cipher_response.getdata()
        split = data_not_splited.find(b" ")
        packet_size = int.from_bytes(data_not_splited[:split], 'big')
        org_size = len(data_not_splited[split+1:])

        size = org_size
        encrypted_data = b''
        while(packet_size != size):
            if((packet_size - size < 0)):
                raise Exception("This is a problem with implementation it. Packets not handled properly")
            remaining = self._not_safe_connection.recv(packet_size - size)
            if(packet_size - size == 0):
                break
            if(remaining):
                self.closeconnection()
                ip, port = self._not_safe_connection.conninfo()
                Logger.log("Connection {}:{} failed or was shutdown".format(ip, port), LogType.INFO)
                return Response(True)
            encrypted_data += remaining.getdata()
            size = org_size + len(encrypted_data)

        decrypted_response = self._enc_interface.decrypt(data_not_splited[split+1:] + encrypted_data)
        if (decrypted_response):
            Logger.log("Failed to decrypt unknown_server_data. Does that suggest tampering?", LogType.WARNING)
            self.closeconnection()
            return Response(True)
        return Response(False, decrypted_response.getdata())

    def allpacketstoend(self) -> []:
        prev_data = b''
        while True:
            one_packet_response = self.listenonepacket()
            if(one_packet_response):
                return []
            data = one_packet_response.getdata()
            if(b'END' in data):
                return (prev_data + data).split(b"\n")
            prev_data = prev_data + data

    def connectiontype(self) -> str:
        return self._enc_interface.connectiontype()

    def getnotsafeconnection(self) -> NotSafeConnection:
        return self._not_safe_connection

    def getencinterface(self) -> RsaCommons.EncryptionInterface:
        return self._enc_interface

    def setnewencinterface(self, interface: RsaCommons.EncryptionInterface):
        self._enc_interface = interface


class ValidActions(Enum):
    # --initalization
    # Server sends it, with randomdata:datetime must be signed by client.
    trustmebro = bytes("trustmebro", "utf-8")

    # on first _notSafeConnection i need to authenticate somehow. Use public key
    authpublic = bytes("authpublic", "utf-8")

    # registerusing code
    registercode = bytes("registercode", "utf-8")

    # self explanatory
    initsymmetric = bytes("initsymmetric", "utf-8")
    # self explanatory
    initpub = bytes("initpub", "utf-8")
    # --------------
    # sftp commands
    sftpls = bytes("sftpls", "utf-8")
    sftpget = bytes("sftpget", "utf-8")
    sftpgetcompressed = bytes("sftpgetcompressed", "utf-8")
    sftupload = bytes("sftupload", "utf-8")
    sftprawls = bytes("sftprawls", "utf-8")

    # Benchmark
    benchmarkpls = bytes("benchmarkpls", "utf-8")
    benchmarkcompressedpls = bytes("benchmarkcompressedpls", "utf-8")
    ping = bytes("ping", "utf-8")
