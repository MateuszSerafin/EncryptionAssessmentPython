import os
from Crypto.Hash import SHA512
from commons import RsaCommons
from commons import Utils
import tqdm


class HostedFiles:
    _path: os.path
    _files = []
    _handles_amnt = {}

    @staticmethod
    def getfiles():
        return HostedFiles._files

    @staticmethod
    def getfilehandle(file_index: int) -> (bool, Utils.FileMetaData, open):
        # I know that it can be called with negative index
        # Also someone calling it must close it after wards
        # I know its an issue
        try:
            meta_data: Utils.FileMetaData = HostedFiles._files[file_index]
            HostedFiles._handles_amnt[meta_data.getfilename()]['handles'] += 1
            return False, meta_data, open(os.path.join(HostedFiles._path, meta_data.getfilename()), 'rb')
        except Exception as e:
            print(e)
            return True, None, None

    @staticmethod
    def closehandle(meta_data: Utils.FileMetaData, opened_file: open):
        data_dict = HostedFiles._handles_amnt[meta_data.getfilename()]
        data_dict['handles'] -= 1
        opened_file.close()
        # I had idea on how to implement it better but i am not wasting 3 hours on this.
        if(data_dict['handles'] == 0 and data_dict['toberemoved']):
            HostedFiles._files.remove(meta_data)
            os.remove(os.path.join(HostedFiles._path, meta_data.getfilename()))
            del HostedFiles._handles_amnt[meta_data.getfilename()]

    @staticmethod
    def addfile(meta_data: Utils.FileMetaData):
        HostedFiles._files.append(meta_data)
        HostedFiles._handles_amnt[meta_data.getfilename()] = {"handles": 0, "toberemoved": False}

    @staticmethod
    def deleteormarkfilefordeletion():
        while True:
            non0start = 1
            for metadata in HostedFiles._files:
                metadata: Utils.FileMetaData
                print(str(non0start) + ". " + metadata.getfilename() + ", SHA512: " + metadata.getchecksum(),
                      ", size in MB: " + str(metadata.getsize() / 1024 / 1024))
                non0start += 1

            selected_file_nbr: int = None

            while selected_file_nbr is None:
                check = input("Please select file to delete or press Q/q to quit: ")
                if (check.lower() == "q"):
                    return False
                if (not check.isdigit()):
                    continue
                check = int(check)
                if (check <= 0):
                    continue

                if (check > len(HostedFiles._files)):
                    continue
                selected_file_nbr = check - 1
                break

            meta_data = HostedFiles._files[selected_file_nbr]
            handles = HostedFiles._handles_amnt[meta_data.getfilename()]['handles']
            if(handles == 0):
                HostedFiles._files.remove(meta_data)
                os.remove(os.path.join(HostedFiles._path, meta_data.getfilename()))
                del HostedFiles._handles_amnt[meta_data.getfilename()]
                print("Sucessfully removed file {}".format(meta_data.getfilename()))
            else:
                print("{} connection(s) currently download this file 2. It's marked as to be deleted. When last connection downloads file fully, the file will be removed".format(handles))
                # TODO there should be hardcore version of it where it prompts server for user to wait with deletion or just remove 0 scrap it as it is even erroring clients
                # Unfourunately it is that it is.
                HostedFiles._handles_amnt[meta_data.getfilename()]['toberemoved'] = True
            break

    @staticmethod
    def initialize(server_file_dir: os.path, server_keywrapper: RsaCommons.PublicPrivateKeyWrapper):
        try:
            HostedFiles._path = server_file_dir
            for file_name in os.listdir(server_file_dir):
                print("Calculating checksum for: " + file_name)
                full_path = os.path.join(server_file_dir, file_name)
                sha_sum = SHA512.new()
                file = open(full_path, "rb")
                size_of_file = os.path.getsize(full_path)
                # Probably should detect if file is above certain size then chunky read.
                # Let's be honest it's still overkill
                # It's fine as it is
                with tqdm.tqdm(total=size_of_file, unit='B', unit_scale=True, unit_divisor=1024) as progress:
                    while True:
                        data = file.read(4096)
                        sha_sum.update(data)
                        if not data:
                            break
                        progress.update(len(data))
                file.close()
                print("Check sum is: " + sha_sum.hexdigest())
                sha_digest = sha_sum.hexdigest()
                signature = server_keywrapper.sign(sha_sum)
                HostedFiles.addfile(Utils.FileMetaData(file_name, sha_digest, signature, size_of_file))
            print("Successfully got checksums of all files")
        except Exception as e:
            print(e)
            raise Utils.FatalError("There was an issue with checking files that server is supposed to share")
