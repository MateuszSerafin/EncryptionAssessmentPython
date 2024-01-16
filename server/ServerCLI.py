from commons import SocketCommons
from commons.Logger import Logger
from server.Authentication import Authentication
from commons import Utils
from server import ServerFiles


def callthatwithmainthread():
    while True:
        print("------------------------------------------")
        print("Select 1 to see active clients")
        print("Select 2 to list logs.")
        print("Select 3 to delete a file")
        print("Select 4 to generate code and allow client to register")
        print("Select 5 to shutdown server")
        print("------------------------------------------")
        action = input("Please select your action:")
        if (not action.isnumeric()):
            print("Your action is incorrect please select correct number")
            continue

        action = int(action)
        if (action == 1):
            mainoption1()
            continue
        if (action == 2):
            how_much_log: int
            while True:
                to_check = input("Please tell me how many last lines of log you want to see (0 for all logs): ")
                if(not to_check.isdigit()):
                    continue
                how_much_log = int(to_check)
                break
            Logger.printlog(how_much_log)
            continue
        if(action == 3):
            ServerFiles.HostedFiles.deleteormarkfilefordeletion()
            continue

        if (action == 4):
            Authentication.generatecode(120)
            continue

        if (action == 5):
            raise Utils.UserWantShutdown


def mainoption1():
    client_list = list(SocketCommons.ConnectionManager.connections.keys())

    startindex = 1
    for client in client_list:
        (clientip, clientport) = client
        print("{}. Client IP: {}, Client Port: {}".format(startindex, clientip, clientport))
        startindex += 1
    print("\n")
