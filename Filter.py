import Sniffer

def loadconf(filename='FirewallARC.conf'):  # load the rules from FirewallARC.conf
    file = open(filename, 'r')
    content = file.read()
    file.close()
    rules = content.split("\n")[:-1]
    configuration = []
    for rule in rules:
        tmp = dict()
        for element in rule.split(", "):
            i = element.index(":")
            tmp[element[:i]] = element[i + 2:]
        configuration.append(tmp)
    return configuration

def Log_dropped(ip):
    with open("Logs_dropped.txt", "a") as f:
        f.write(f"[{ip} - Dropped] -> reason: matching with the selected rules\n")
        f.close()

def firewall(packet):  # compare the packet and the rules. Return True if it's accept or False if it's drop
    configuration = loadconf()
    if len(configuration) == 0:
        return True
    else:
        for rules in configuration:
            test = []
            for rule in rules:
                if rule in packet:
                    test.append(packet[rule] == rules[rule])
            if test.count(True) == 1:
                for rule in rules:
                    if rule in packet:
                        Log_dropped(packet[rule])
                return False
        return True

class Packet:  # Packet management as object

    index = 0

    def __init__(self, infos):
        self.__info = {"id": Packet.index + 1}
        Packet.index += 1
        for info in infos:
            self.__info[info] = infos[info]
        self.__info["action"] = firewall(self.__info)

    def getid(self):
        return str(self.__info["id"])

    def getinfo(self, info):
        try:
            return self.__info[info]
        except:
            return ""

    def getall(self):
        return self.__info.copy()

    def setinfo(self, name, value):
        self.__info[name] = value

    def isempty(self):
        tmp = 0
        for element in self.__info:
            if self.__info[element] != "":
                tmp += 1
        if tmp > 2:
            return False
        return True
