import os
from commons import PersistentStorage
from server import ServerHandler
from commons import Utils
from server import ServerCLI
from commons import Logger
from server import ServerFiles
from server.Authentication import Authentication


if __name__ == "__main__":
    #Please, don't initialize anything there.
    #Any input etc should be inside __init__
    try:
        Pstorage = PersistentStorage.PersistentStore("server")

        log = Pstorage.getorcreatedata("log")
        Logger.Logger._load(log)

        auth = Pstorage.getorcreatedata("auth")
        Authentication._load(auth)

        ServerFiles.HostedFiles.initialize("ftpData", Pstorage.getstoredwrapper())

        Shandler = ServerHandler.ServerHandleClass(Pstorage)
        ServerCLI.callthatwithmainthread()

    except (Utils.UserWantShutdown,Utils.FatalError) as e:
        #error prints message, fatal error doesnt do anything, just quits, userwantsshutdown saves everything.
        e.printerror()
        if(isinstance(e, Utils.UserWantShutdown)):
            Pstorage.save()
        #Without it it wait for other threads, as i know python threads are funny i am not messing around and try to shut them down.
        os._exit(1)
