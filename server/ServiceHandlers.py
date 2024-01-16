import base64
import json
import lzma
import os.path
from commons import RsaCommons
from commons import SocketCommons
from commons.Logger import Logger, LogType
from server import ServerFiles
from commons import Utils
from Crypto.Hash import SHA512
from lzma import LZMACompressor


def _handlesftpls(safe_conn: SocketCommons.SafeConnection):
    Logger.log("Client {}:{} requested to view files".format(*safe_conn.getnotsafeconnection().conninfo()), LogType.INFO)

    deserialize = []
    for metadata in ServerFiles.HostedFiles.getfiles():
        metadata: Utils.FileMetaData
        deserialize.append([metadata.getfilename(), metadata.getchecksum(), base64.b64encode(metadata.getsignature()).decode("utf-8"), metadata.getsize()])

    to_send = base64.b64encode(bytes(json.dumps(deserialize), 'utf-8')) + b"\n" + b"END"
    if(not safe_conn.sendencrypted(to_send)):
        return True
    return False


def _handlesftpget(safe_conn: SocketCommons.SafeConnection, selected_digit):
    selected = base64.b64decode(selected_digit)
    if(not selected.isdigit()):
        return True
    failed, metadata, readable = ServerFiles.HostedFiles.getfilehandle(int(selected))
    if(failed):
        Logger.log("Client {}:{} requested a file that doesn't exist".format(*safe_conn.getnotsafeconnection().conninfo()), LogType.WARNING)
        return True
    Logger.log("Client {}:{} requested {}".format(*safe_conn.getnotsafeconnection().conninfo(), metadata.getfilename()), LogType.INFO)
    while True:
        chunk_read = readable.read(safe_conn.getencinterface().sendsize() * 8)
        if not chunk_read:
            ServerFiles.HostedFiles.closehandle(metadata, readable)
            break
        if (not safe_conn.sendencrypted(chunk_read)):
            ServerFiles.HostedFiles.closehandle(metadata, readable)
            return True
    return False


def _handlecompressedsftpget(safe_conn: SocketCommons.SafeConnection, selected_digit):
    # https://docs.python.org/3/library/lzma.html
    filters = [dict(id=lzma.FILTER_DELTA, dist=4),
               dict(id=lzma.FILTER_X86),
               dict(id=lzma.FILTER_LZMA2, preset=9, dict_size=2**28)
    ]
    compressor = LZMACompressor(format=lzma.FORMAT_RAW,filters=filters)
    selected = base64.b64decode(selected_digit)
    if(not selected.isdigit()):
        return True
    failed, metadata, readable = ServerFiles.HostedFiles.getfilehandle(int(selected))
    if(failed):
        Logger.log("Client {}:{} requested a file that doesn't exist".format(*safe_conn.getnotsafeconnection().conninfo()), LogType.WARNING)
        return True
    Logger.log("Client {}:{} requested {}".format(*safe_conn.getnotsafeconnection().conninfo(), metadata.getfilename()), LogType.INFO)
    left_over = b''
    while True:
        chunk_read = readable.read(safe_conn.getencinterface().sendsize() * 8)

        if(not chunk_read):
            flushed = compressor.flush()
            if (not safe_conn.sendencrypted(left_over + len(flushed).to_bytes(3, 'big') + b' ' + flushed + b"\n")):
                ServerFiles.HostedFiles.closehandle(metadata, readable)
                return True
            ServerFiles.HostedFiles.closehandle(metadata, readable)
            break

        compressed = compressor.compress(chunk_read)
        if(compressed == b''):
            continue
        chunk_compressed_base64 = left_over + len(compressed).to_bytes(3, 'big') + b' ' + compressed + b"\n"
        for index in range(0, len(chunk_compressed_base64), safe_conn.getencinterface().sendsize()):
            chunk_compressed = chunk_compressed_base64[index:index+safe_conn.getencinterface().sendsize()]
            if(len(chunk_compressed) != safe_conn.getencinterface().sendsize()):
                left_over = chunk_compressed
                # should be last part either way
                break
            if (not safe_conn.sendencrypted(chunk_compressed)):
                ServerFiles.HostedFiles.closehandle(metadata, readable)
                return True
    return False


# The difference between that and sftpls is that ls would show files that are aviable to download. This shows files that are currently in directory (when someeone uploads, before it will be processed its in this state)
def _handlesftpcurrentfiles(safe_conn: SocketCommons.SafeConnection):
    client_overwrite_detection = base64.b64encode(bytes(json.dumps(os.listdir(ServerFiles.HostedFiles._path)), 'utf-8')) + b"\nEND"
    if(not safe_conn.sendencrypted(client_overwrite_detection)):
        return True


def _handlesftpupload(safe_conn: SocketCommons.SafeConnection, data, public_private_server: RsaCommons.PublicPrivateKeyWrapper):
    try:
        decoded = base64.b64decode(data)
        json_dict = json.loads(decoded)
        if('filename' not in json_dict or 'size' not in json_dict):
            raise
    except Exception:
        Logger.log("{}:{} wanted to upload file however did not send valid information about file.".format(*safe_conn.getnotsafeconnection().conninfo()), LogType.WARNING)
        safe_conn.closeconnection()
        return True


    safe_file_name = os.path.basename(json_dict['filename'])
    if(os.path.exists(os.path.join(ServerFiles.HostedFiles._path, safe_file_name))):
        return True

    if(not safe_conn.sendencrypted(b'ack\nEND')):
        Logger.log("Could not agree with {}:{} client when to download file.".format(*safe_conn.getnotsafeconnection().conninfo()), LogType.WARNING)
        safe_conn.closeconnection()
        return True
        
    # Exactly after data signature is being send
    data_got = 0
    sha_sum = SHA512.new()
    writable = open(os.path.join(ServerFiles.HostedFiles._path, safe_file_name), 'wb')

    while True:
        server_response = safe_conn.listenonepacket()
        if server_response:
            safe_conn.closeconnection()
            writable.flush()
            writable.close()
            os.remove(os.path.join(ServerFiles.HostedFiles._path, safe_file_name))
            return True

        sha_sum.update(server_response.getdata())
        data_got += len(server_response.getdata())
        writable.write(server_response.getdata())

        if(data_got == json_dict['size']):
            writable.flush()
            writable.close()
            break

    # Client should send signature past this point
    if (not safe_conn.sendencrypted(b'ack\nEND')):
        Logger.log("Client {}:{} could not agree about sending signature.".format(*safe_conn.getnotsafeconnection().conninfo()), LogType.WARNING)
        os.remove(os.path.join(ServerFiles.HostedFiles._path, safe_file_name))
        return True

    signature = safe_conn.allpacketstoend()
    if(signature[-1] != b'END'):
        Logger.log("Client {}:{} did not send signature properly.".format(*safe_conn.getnotsafeconnection().conninfo()), LogType.WARNING)
        os.remove(os.path.join(ServerFiles.HostedFiles._path, safe_file_name))
        return True

    authorized_key: RsaCommons.EncryptOnlyPublic = SocketCommons.ConnectionManager.connections[safe_conn.getnotsafeconnection().conninfo()]['authorizepublickey']

    try:
        if(not authorized_key.verifysignature(sha_sum, base64.b64decode(signature[0]))):
            Logger.log("Client {}:{} send file which signature didn't match. Is that an attack?".format(*safe_conn.getnotsafeconnection().conninfo()), LogType.SEVERE)
            os.remove(os.path.join(ServerFiles.HostedFiles._path, safe_file_name))
            return True
    except Exception:
        Logger.log("Client {}:{} send file which signature didn't match. Is that an attack?".format(*safe_conn.getnotsafeconnection().conninfo()), LogType.SEVERE)
        os.remove(os.path.join(ServerFiles.HostedFiles._path, safe_file_name))
        return True

    ServerFiles.HostedFiles.addfile(Utils.FileMetaData(safe_file_name, sha_sum.hexdigest(), public_private_server.sign(sha_sum), json_dict['size']))
    return False


def _handlebenchmark(safe_conn: SocketCommons.SafeConnection):
    # TODO there should be a limit like 10 minutes per authenticated user.
    Logger.log("Client {}:{} requested benchmark".format(*safe_conn.getnotsafeconnection().conninfo()), LogType.INFO)

    how_many_packets = int(40910102 / safe_conn.getencinterface().sendsize())

    # Yes sending only ones is the best thing that i come up with
    fake_data = b'1' * (safe_conn.getencinterface().sendsize() - 1)

    # on client side it looks nicer
    for i in range(1, how_many_packets):
        if (not safe_conn.sendencrypted(fake_data + b"\n")):
            return True

    if (not safe_conn.sendencrypted(b"END")):
        return True
    return False


def _handlecompressedbenchmark(safe_conn: SocketCommons.SafeConnection):
    # above benchmark won t work or it will make fake data thats why it s done this way
    data_send = 0

    filters = [
        dict(id=lzma.FILTER_DELTA, dist=4),
        dict(id=lzma.FILTER_X86),
        dict(id=lzma.FILTER_LZMA2, preset=9, dict_size=2**28)
    ]
    compressor = LZMACompressor(format=lzma.FORMAT_RAW, filters=filters)

    send_size = safe_conn.getencinterface().sendsize() * 8
    left_over = b''

    while data_send < 40910102:
        remaining_size = 40910102 - data_send
        current_chunk_size = min(send_size, remaining_size)
        chunk_read = os.urandom(current_chunk_size)
        data_send += len(chunk_read)
        compressed = compressor.compress(chunk_read)
        if(compressed == b''):
            continue
        chunk_compressed_base64 = left_over + len(compressed).to_bytes(3, 'big') + b' ' + compressed + b"\n"
        for index in range(0, len(chunk_compressed_base64), safe_conn.getencinterface().sendsize()):
            chunk_compressed = chunk_compressed_base64[index:index+safe_conn.getencinterface().sendsize()]
            if(len(chunk_compressed) != safe_conn.getencinterface().sendsize()):
                left_over = chunk_compressed
                # should be last part either way
                break
            if (not safe_conn.sendencrypted(chunk_compressed)):
                return True
    flushed = compressor.flush()
    if (not safe_conn.sendencrypted(left_over + len(flushed).to_bytes(3, 'big') + b' ' + flushed + b"\n")):
        return True
    return False


def _handleping(safe_conn: SocketCommons.SafeConnection):
    Logger.log("Client {}:{} ponged server".format(*safe_conn.getnotsafeconnection().conninfo()), LogType.INFO)

    if (not safe_conn.sendencrypted(b"\nEND")):
        return True


def eachthreadcallsthat(safe_connection: SocketCommons.SafeConnection, public_private_server: RsaCommons.PublicPrivateKeyWrapper):
    # Handle till client disconnects
    # Also server does nothing just responds to client so this is correct
    while True:
        data = safe_connection.allpacketstoend()
        if(data == []):
            Logger.log("Client {}:{} failed or disconnected.".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
            safe_connection.closeconnection()
            return
        if(data[-1] != b'END'):
            Logger.log("Server received incorrect packet from {}:{}".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
            safe_connection.closeconnection()
            return

        if(data[0] == SocketCommons.ValidActions.sftpls.value):
            if(_handlesftpls(safe_connection)):
                Logger.log("Server failed to send packet to {}:{}".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
                safe_connection.closeconnection()
                return
            continue

        if(data[0] == SocketCommons.ValidActions.sftpget.value):
            if(_handlesftpget(safe_connection, data[1])):
                Logger.log("Server failed to send packet to {}:{}".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
                safe_connection.closeconnection()
                return
            continue

        if(data[0] == SocketCommons.ValidActions.sftpgetcompressed.value):
            if(_handlecompressedsftpget(safe_connection, data[1])):
                Logger.log("Server failed to send packet to {}:{}".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
                safe_connection.closeconnection()
                return
            continue

        if(data[0] == SocketCommons.ValidActions.benchmarkpls.value):
            if(_handlebenchmark(safe_connection)):
                Logger.log("Server failed to send packet to {}:{}".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
                safe_connection.closeconnection()
                return
            continue

        if(data[0] == SocketCommons.ValidActions.benchmarkcompressedpls.value):
            if(_handlecompressedbenchmark(safe_connection)):
                Logger.log("Server failed to send packet to {}:{}".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
                safe_connection.closeconnection()
                return
            continue

        if(data[0] == SocketCommons.ValidActions.sftprawls.value):
            if(_handlesftpcurrentfiles(safe_connection)):
                Logger.log("Server failed to send packet to {}:{}".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
                safe_connection.closeconnection()
                return
            continue

        if(data[0] == SocketCommons.ValidActions.sftupload.value):
            if(_handlesftpupload(safe_connection, data[1], public_private_server)):
                Logger.log("Server failed to send packet to {}:{}".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
                safe_connection.closeconnection()
                return
            continue

        if(data[0] == SocketCommons.ValidActions.ping.value):
            if(_handleping(safe_connection)):
                Logger.log("Server failed to send packet to {}:{}".format(*safe_connection.getnotsafeconnection().conninfo()), LogType.WARNING)
                safe_connection.closeconnection()
                return
            continue
