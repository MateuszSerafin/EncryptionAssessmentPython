import datetime
from enum import Enum
from commons.Utils import Bcolors


class LogType(Enum):
    INFO = 0
    WARNING = 1
    SEVERE = 2


# I don't want to make instances of that
class Logger:
    _data: list

    # Shouldn't have problems with saving as it's just reference to persistent storage
    @staticmethod
    def _load(data):
        Logger._data = data

    @staticmethod
    def log(what: str, severity: LogType):
        Logger._data.append((datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"), what, severity.value))

    @staticmethod
    def _actuallyprintlinepretty(what_line):
        date, info, logtype = what_line
        # Bcolors should be enum, but in my use case it literary barerly matters
        # Will just hard code it

        # TODO maybe add like separation between days
        # For now i want to store date as string as it will be bz2 compressed should be better than whole object i guess
        what = ""
        if(logtype == 0):
            what = Bcolors.INFO
        if(logtype == 1):
            what = Bcolors.WARNING
        if(logtype == 2):
            what = Bcolors.SEVERE
        print(what + date + " " + info + Bcolors.ENDC)

    @staticmethod
    def printlog(last_line_limit: int = 0):
        if(last_line_limit == 0):
            for line in Logger._data:
                Logger._actuallyprintlinepretty(line)

        size = len(Logger._data)
        for line in Logger._data[size - last_line_limit:size]:
            Logger._actuallyprintlinepretty(line)
