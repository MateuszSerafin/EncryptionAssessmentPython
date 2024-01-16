import base64
import datetime
import json
import lzma
import queue
import pythonping
from commons import SocketCommons
from commons import RsaCommons
from commons.Logger import Logger
from commons import Utils
import tqdm
from Crypto.Hash import SHA512
import os
from lzma import LZMADecompressor


def callthatwithmainthread(safe_connection: SocketCommons.SafeConnection, server_public_key: RsaCommons.EncryptOnlyPublic, client_wrapped: RsaCommons.PublicPrivateKeyWrapper):
    while True:
        # Perform check if it's running on each gui update
        if(not safe_connection.getnotsafeconnection().conninfo() in SocketCommons.ConnectionManager.connections):
            raise Utils.FatalError("Connection got interrupted, perhaps server closed connection")

        print("------------------------------------------")
        print("Select 1 to list logs")
        print("Select 2 to download files from server")
        print("Select 3 to upload file to server")
        print("Select 4 to perform bandwidth test")
        print("Select 5 to perform ping (ICMP)")
        print("Select 6 to perform ping (encrypted)")
        print("Select 9 to shutdown client")
        print("------------------------------------------")
        action = input("Please select your action:")
        if (not action.isnumeric()):
            print("Your action is incorrect please select correct number")
            continue

        action = int(action)
        if (action == 1):
            last_lines: int = 0
            while True:
                tocheck = input("Please tell me how many last lines of log you want to see (0 for all logs): ")
                if(not tocheck.isdigit()):
                    continue
                last_lines = int(tocheck)
                break
            Logger.printlog(last_lines)
            continue
        if (action == 2):
            main_option2(safe_connection, server_public_key)
            continue

        if(action == 3):
            mainoption3(safe_connection, client_wrapped)
            continue

        if(action == 4):
            mainoption4(safe_connection)
            continue

        if(action == 5):
            print(pythonping.ping(safe_connection._not_safe_connection.conninfo()[0]))
            continue

        if(action == 6):
            mainoption6(safe_connection)
            continue

        if (action == 9):
            safe_connection.closeconnection()
            raise Utils.UserWantShutdown


def main_option2(safe_connection: SocketCommons.SafeConnection, server_public_key: RsaCommons.EncryptOnlyPublic):
    to_send = SocketCommons.ValidActions.sftpls.value + b"\n" + b"END"
    if(not safe_connection.sendencrypted(to_send)):
        raise Utils.FatalError("Couldn't send data to server")

    sftp_ls_sresponse = safe_connection.allpacketstoend()
    if(len(sftp_ls_sresponse) != 2):
        raise Utils.FatalError("Client failed to receive data from server")

    non0start = 1
    files = []

    try:
        data = json.loads(base64.b64decode(sftp_ls_sresponse[0]))
    except Exception:
        raise Utils.FatalError("There was an issue parsing data, server send unexpected information")

    for tple in data:
        files.append(Utils.FileMetaData(tple[0], tple[1], base64.b64decode(tple[2]), tple[3]))
    for metadata in files:
        metadata: Utils.FileMetaData
        print(str(non0start) + ". " + metadata.getfilename() + ", SHA512: " + metadata.getchecksum(), ", size in MB: " + str(metadata.getsize() / 1024 / 1024))
        non0start += 1

    selected_file_nbr: bytes = None

    while selected_file_nbr is None:
        check = input("Please select your file or press Q/q to quit: ")
        if(check.lower() == "q"):
            return False
        if(not check.isdigit()):
            continue
        check = int(check)
        if(check <= 0):
            continue

        if(check > len(files)):
            continue

        selected_file_nbr = bytes(str(check - 1), "utf-8")
        break

    print("You are trying to download file")
    print("Select 1 for normal download")
    print("Select 2 for compressed download (really slow, saves data depending on file type)")
    user_input_good = None
    while(user_input_good == None):
        user_input = input("Please type your option: ")
        if(not user_input.isdigit()):
            continue
        user_input = int(user_input)
        if(user_input == 1):
            user_input_good = 1
        if(user_input == 2):
            user_input_good = 2
        continue
    if(user_input_good == 1):
        to_send = SocketCommons.ValidActions.sftpget.value + b"\n" + base64.b64encode(
            selected_file_nbr) + b"\n" + b'END'
        if (not safe_connection.sendencrypted(to_send)):
            raise Utils.FatalError("Could not send data to server.")

        metadata = files[int(selected_file_nbr)]

        if (not os.path.exists("clientDownloads")):
            os.mkdir("clientDownloads")
        writable_file = open(os.path.join("clientDownloads", metadata.getfilename()), "wb")

        with tqdm.tqdm(total=metadata.getsize(), unit='B', unit_scale=True, unit_divisor=1024) as progress:
            sha_sum = SHA512.new()
            data_recv = 0
            while True:
                server_response = safe_connection.listenonepacket()
                if server_response:
                    safe_connection.closeconnection()

                    return True

                sha_sum.update(server_response.getdata())
                update_size = len(server_response.getdata())
                data_recv += update_size
                writable_file.write(server_response.getdata())
                progress.update(update_size)

                if (data_recv == metadata.getsize()):
                    break

            if (not server_public_key.verifysignature(sha_sum, metadata.getsignature())):
                writable_file.close()
                os.remove(metadata.getfilename())
                raise Utils.FatalError(
                    "Could not verify file {} signature does not match.".format(metadata.getfilename()))

            writable_file.flush()
            writable_file.close()
            return False
    if(user_input_good == 2):
        to_send = SocketCommons.ValidActions.sftpgetcompressed.value + b"\n" + base64.b64encode(
            selected_file_nbr) + b"\n" + b'END'
        if (not safe_connection.sendencrypted(to_send)):
            raise Utils.FatalError("Could not send data to server.")

        metadata = files[int(selected_file_nbr)]

        if (not os.path.exists("clientDownloads")):
            os.mkdir("clientDownloads")
        writable_file = open(os.path.join("clientDownloads", metadata.getfilename()), "wb")

        with tqdm.tqdm(total=metadata.getsize(), unit='B', unit_scale=True, unit_divisor=1024) as progress:
            filters = [dict(id=lzma.FILTER_DELTA, dist=4),
                       dict(id=lzma.FILTER_X86),
                       dict(id=lzma.FILTER_LZMA2, preset=9, dict_size=2 ** 28)
                       ]

            decompressor = LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
            sha_sum = SHA512.new()
            # calculating difference between compression and how much received
            data_recv = 0
            size_of_compressed_data = 0

            packets = 0
            # extraction data from packets
            client_data = queue.Queue()

            server_response = safe_connection.listenonepacket()
            if (server_response):
                raise Utils.FatalError("Failed communication with server")
            for character in server_response.getdata():
                client_data.put(character)

            while True:
                # Finished
                if(data_recv == metadata.getsize()):
                    break

                how_many_needed = []
                how_many_left = 0
                while True:
                    if(client_data.empty()):
                        server_response = safe_connection.listenonepacket()
                        packets += 1
                        if (server_response):
                            raise Utils.FatalError("Failed communication with server")
                        for character in server_response.getdata():
                            client_data.put(character)

                    character = client_data.get()
                    if(character == 32):
                        how_many_left = int.from_bytes(how_many_needed, 'big')
                        break
                    how_many_needed.append(character)

                # If server says that there is more data there must be more data
                while (how_many_left > client_data.qsize()):
                    server_response = safe_connection.listenonepacket()
                    packets += 1
                    if (server_response):
                        raise Utils.FatalError("Failed communication with server")
                    for character in server_response.getdata():
                        client_data.put(character)

                one_chunk = []
                for i in range(how_many_left):
                    one_chunk.append(client_data.get())
                decompressed = decompressor.decompress(bytes(one_chunk))
                size_of_compressed_data += len(bytes(one_chunk))
                sha_sum.update(decompressed)
                update_size = len(decompressed)
                data_recv += update_size
                writable_file.write(decompressed)
                progress.update(update_size)

                # next from queue should be new line as in server implementation
                trust_me_bro = client_data.get()
                if(trust_me_bro != 10):
                    writable_file.flush()
                    writable_file.close()
                    os.remove(metadata.getfilename())
                    raise Utils.FatalError("Server send incorrect data expected something different")
                continue

            if (not server_public_key.verifysignature(sha_sum, metadata.getsignature())):
                writable_file.close()
                os.remove(metadata.getfilename())
                raise Utils.FatalError("Could not verify file {} signature does not match.".format(metadata.getfilename()))

            how_much_saved = (data_recv - size_of_compressed_data) / 1024 / 1024
            if(how_much_saved > 0):
                print("By using compression you reduced you data usage by {}Mb".format(how_much_saved))
            else:
                print("Your data doesn't compress well there fore by using compression you send more data. Lost {}Mb".format(how_much_saved))
            writable_file.flush()
            writable_file.close()
            return False
        raise


def mainoption3(safe_connection: SocketCommons.SafeConnection, client_wrrapped: RsaCommons.PublicPrivateKeyWrapper):
    file_to_upload = input("Please type path of file you want to upload or press enter to cancel: ")
    if(file_to_upload == ''):
        return False

    if(not os.path.exists(file_to_upload)):
        print("You tried to upload file that doesn't exist please try again")

    if(not os.path.isfile(file_to_upload)):
        print("Path that you provided doesn't seem to be a file. Please try again")

    if(not safe_connection.sendencrypted(SocketCommons.ValidActions.sftprawls.value + b"\nEND")):
        raise Utils.FatalError("Could not send packet to server")

    currently_existing_files_on_server = safe_connection.allpacketstoend()

    try:
        currently_existing_files_on_server = json.loads(base64.b64decode(currently_existing_files_on_server[0]))
    except Exception:
        raise Utils.FatalError("Could not determine what files server currently has")

    size = os.path.getsize(file_to_upload)
    filename = os.path.basename(file_to_upload)

    if(filename in currently_existing_files_on_server):
        print("File that you provided currently exists on server.")
        what_to_do = input("Please put new name of the file or enter to cancel upload: ")
        if(what_to_do == ''):
            return False
        # Clean not error prone code <- i lost hopes with this commit, either way server should error if it doesnt like name of this file and drop connection.
        filename = what_to_do

    if(not safe_connection.sendencrypted(SocketCommons.ValidActions.sftupload.value + b"\n" + base64.b64encode(bytes(json.dumps({'filename': filename, 'size': size}), 'utf-8'))+b'\nEND')):
        raise Utils.FatalError("Could not send filemetadata to server")

    server_ack = safe_connection.allpacketstoend()
    if(server_ack[0] != b'ack'):
        raise Utils.FatalError("Server did not ack next step cannot proceed.")
    sha_sum = SHA512.new()
    with tqdm.tqdm(total=size, unit='B', unit_scale=True, unit_divisor=1024) as progress:
        readable = open(file_to_upload, 'rb')
        while True:
            chunk_read = readable.read(safe_connection.getencinterface().sendsize() * 8)
            if not chunk_read:
                readable.flush()
                readable.close()
                break
            if (not safe_connection.sendencrypted(chunk_read)):
                readable.flush()
                readable.close()
                raise Utils.FatalError("Lost connection to server while transmitting file")
            sha_sum.update(chunk_read)
            progress.update(len(chunk_read))

    server_ack = safe_connection.allpacketstoend()
    if(server_ack[0] != b'ack'):
        raise Utils.FatalError("Server did not ack next step cannot proceed.")

    if(not safe_connection.sendencrypted(base64.b64encode(client_wrrapped.sign(sha_sum)) + b'\nEND')):
        raise Utils.FatalError("Could not send signature to server")


def mainoption4(safe_connection: SocketCommons.SafeConnection):
    # idea was good but compressing random data is really bad
    # it will just look better to keep it without benchmark.
    # Server has still functionality for it just uncomment it
    #print("You are trying to perform bencchmark")
    #print("Select 1 for benchmark without compression")
    #print("Select 2 for benchmark with compression")
    user_input_good = 1
    #user_input_good = 0
    #while(user_input_good == None):
    #    user_input = input("Please type your option: ")
    #    if(not user_input.isdigit()):
    #        continue
    #    user_input = int(user_input)
    #    if(user_input == 1):
    #        user_input_good = 1
    #    if(user_input == 2):
    #        user_input_good = 2
    #    continue
    if(user_input_good == 1):
        to_send = SocketCommons.ValidActions.benchmarkpls.value + b"\nEND"
        if(not safe_connection.sendencrypted(to_send)):
            raise Utils.FatalError("Couldn't send data to server")

        how_many_packets = int(40910102 / safe_connection.getencinterface().sendsize())
        with tqdm.tqdm(total=how_many_packets * safe_connection.getencinterface().sendsize(), unit='B', unit_scale=True, unit_divisor=1024) as progress:

            for i in range(how_many_packets):
                response = safe_connection.listenonepacket()
                if(response):
                    raise Utils.FatalError("Server closed connection")
                actually_needed_data = response.getdata().split(b'END')
                if(len(actually_needed_data) > 1):
                    progress.update(len(actually_needed_data[0]))
                    break
                progress.update(len(response.getdata()))

            return False
    if(user_input_good == 2):
        to_send = SocketCommons.ValidActions.benchmarkcompressedpls.value + b"\nEND"
        if(not safe_connection.sendencrypted(to_send)):
            raise Utils.FatalError("Couldn't send data to server")

        with tqdm.tqdm(total=40910102, unit='B', unit_scale=True, unit_divisor=1024) as progress:
            filters = [dict(id=lzma.FILTER_DELTA, dist=4),
                       dict(id=lzma.FILTER_X86),
                       dict(id=lzma.FILTER_LZMA2, preset=9, dict_size=2 ** 28)
                       ]

            decompressor = LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
            sha_sum = SHA512.new()
            # calculating difference between compression and how much received
            data_recv = 0
            size_of_compressed_data = 0

            packets = 0
            # extraction data from packets
            client_data = queue.Queue()

            server_response = safe_connection.listenonepacket()
            if (server_response):
                raise Utils.FatalError("Failed communication with server")
            for character in server_response.getdata():
                client_data.put(character)

            last_loop = False
            while True:
                if(last_loop):
                    break

                # Finished
                if(data_recv == 40910102):
                    last_loop = True
                    break

                how_many_needed = []
                how_many_left = 0
                while True:
                    if(client_data.empty()):
                        server_response = safe_connection.listenonepacket()

                        if (server_response):
                            raise Utils.FatalError("Failed communication with server")
                        for character in server_response.getdata():
                            client_data.put(character)

                    character = client_data.get()
                    if(character == 32):
                        how_many_left = int.from_bytes(how_many_needed, 'big')
                        break
                    how_many_needed.append(character)

                # If server says that there is more data there must be more data
                while (how_many_left > client_data.qsize()):
                    server_response = safe_connection.listenonepacket()
                    if (server_response):
                        raise Utils.FatalError("Failed communication with server")
                    for character in server_response.getdata():
                        client_data.put(character)

                one_chunk = []
                for i in range(how_many_left):
                    one_chunk.append(client_data.get())
                decompressed = decompressor.decompress(bytes(one_chunk))
                size_of_compressed_data += len(bytes(one_chunk))
                sha_sum.update(decompressed)
                update_size = len(decompressed)
                data_recv += update_size
                progress.update(update_size)

                # next from queue should be new line as in server implementation
                trust_me_bro = client_data.get()
                if(trust_me_bro != 10):
                    raise Utils.FatalError("Server send incorrect data expected something different")
                continue

            how_much_saved = (data_recv - size_of_compressed_data) / 1024 / 1024
            if(how_much_saved > 0):
                print("By using compression you reduced you data usage by {}Mb".format(how_much_saved))
            else:
                print("Your data doesn't compress well there fore by using compression you send more data. Lost {}Mb".format(how_much_saved))


def mainoption6(safe_connection: SocketCommons.SafeConnection):
    now_time = datetime.datetime.now()
    if(not safe_connection.sendencrypted(SocketCommons.ValidActions.ping.value + b"\nEND")):
        raise Utils.FatalError("Couldn't send data to server")

    response = safe_connection.listenonepacket()
    if (response):
        raise Utils.FatalError("Server closed connection")

    if(response.getdata() != b'\nEND'):
        raise Utils.FatalError("Server send incorrect data back.")

    print("Encrypted ping time is " + str(datetime.datetime.now() - now_time))
