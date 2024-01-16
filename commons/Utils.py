# https://stackoverflow.com/questions/287871/how-do-i-print-colored-text-to-the-terminal
class Bcolors:
    INFO = '\033[94m'
    WARNING = '\033[31m'
    SEVERE = '\033[91m'
    OKGREEN = '\033[92m'


    TURQOISEBACKGROUNDBLACK = '\033[7;49;36m'
    ENDC = '\033[0m'


class FileMetaData:
    _filename: str
    _sha512: str
    _signature: bytes
    _size_in_bytes: int

    def __init__(self, filename: str,  sha512: str, signature: bytes, sizeinbytes: int):
        self._filename = filename
        self._sha512 = sha512
        self._signature = signature
        self._size_in_bytes = sizeinbytes

    def getfilename(self) -> str:
        return self._filename

    def getchecksum(self) -> str:
        return self._sha512

    def getsignature(self) -> bytes:
        return self._signature

    def getsize(self) -> int:
        return self._size_in_bytes


class UserWantShutdown(Exception):
    def __init__(self, error="User requested shutdown, quitting gracefully."):
        super().__init__(error)
        self.error = error

    def printerror(self):
        print(Bcolors.OKGREEN + self.error + Bcolors.ENDC)


class FatalError(Exception):
    def __init__(self, error="Fatal error occured cannot proceed quitting."):
        super().__init__(error)
        self.error = error

    def printerror(self):
        print(Bcolors.SEVERE + self.error + Bcolors.ENDC)
