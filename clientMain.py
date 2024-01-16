from commons import PersistentStorage
from client import ClientHandler
from commons import Utils
from commons import Logger
from client import ClientCLI
import os


if __name__ == "__main__":
    try:
        Pstorage = PersistentStorage.PersistentStore("client")
        log = Pstorage.getorcreatedata("log")
        Logger.Logger._load(log)

        previousConnected = Pstorage.getorcreatedata("lastConnected", is_dict=True)
        clientHandler = ClientHandler.ClientHandlerClass(previousConnected, Pstorage)
        ClientCLI.callthatwithmainthread(clientHandler.getsafeconnection(), clientHandler.serverpublickey(), Pstorage.getstoredwrapper())

    except (Utils.UserWantShutdown, Utils.FatalError) as e:
        # error prints message, fatal error doesnt do anything, just quits, userwantsshutdown saves everything.
        e.printerror()
        if (isinstance(e, Utils.UserWantShutdown)):
            Pstorage.save()

        # Without it it wait for other threads, as i know python threads are funny i am not messing around and try to shut them down.
        os._exit(1)
