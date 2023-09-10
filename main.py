print("Loading...")
import Interface
import Sniffer
import Filter
from threading import Thread
import socket
import re
import os


print(
"""
 ------------------------------------------------------------------
|This project created by Kevin Fernando a.k.a github.com/xterler159|
 ------------------------------------------------------------------
                        |Modified by iFanpS|
                         ------------------

[Tips] - To show all command list type *help*
       - What i have modified? Type *mod*
""")

class Firewall(Thread):  # Command prompt
    """Command prompt class"""

    interfacelink = []
    cmdlink = []
    program = {"firewall": Sniffer.sniffer(interfacelink, cmdlink), "interface": Interface.Interface(interfacelink)}

    def __init__(self):
        Thread.__init__(self)

    def run(self):  # command management
        running = True
        while running:
            command = input(os.environ['USERNAME'] + " >")
            if command == "mod":
                print("All things that i've been modify\n \
        - Fix Accept and Deny IP Address \
        - Fix FirewallARC config \
        - Adding command such 'start', 'stopall' etc \
        - Adding logs \
        - Fix filtering packet")
            elif command == "start":
                if not self.program["firewall"].is_alive() and not self.program["interface"].is_alive():
                    running = False
                    cmd = Firewall()
                    print("Starting firewall and interface...")
                    self.program["firewall"].running = True
                    self.program["firewall"].start()
                    print("Firewall On")
                    self.program["interface"] = Interface.Interface(self.interfacelink)
                    self.program["interface"].running = True
                    self.program["interface"].start()
                    print("Interface ON")
                    cmd.start()
                else:
                    print("Interface and Firewall is already running...\n[Tips] - Type *show status*")
            elif command == "stopall":
                if not self.program["firewall"].is_alive() and not self.program["interface"].is_alive():
                    print("Interface and firewall already stopped...")
                else:
                    if self.program['firewall'].is_alive():
                        print("Stoping interface and firewall....")
                        self.program["firewall"].running = False
                        self.program["firewall"].join()
                        print("Firewall OFF")
                        self.program["firewall"] = Sniffer.sniffer(self.interfacelink, self.cmdlink)
                    else:
                        check_life = self.program['firewall'].is_alive()
                        print(f"Impossible to shutdown all.\nFirewall status: {check_life}\n\t\t- Tips [type] stop [firewall/interface] manually")
                    if self.program['interface'].is_alive():
                        self.program["interface"].running = False
                        self.program["interface"].join()
                        print("Interface OFF")
                    else:
                        check_life = self.program['interface'].is_alive()
                        print(f"Impossible to shutdown all.\nInterface status: {check_life}\n\t\t- Tips [type] stop [firewall/interface] manually")
            elif command == "start firewall":
                if not self.program["firewall"].is_alive():
                    running = False
                    cmd = Firewall()
                    print("Start...")
                    self.program["firewall"].running = True
                    self.program["firewall"].start()
                    print("Firewall ON")
                    cmd.start()
                else:
                    print("Firewall is already running")
            elif command == "start interface":
                if not self.program["interface"].is_alive():
                    running = False
                    cmd = Firewall()
                    print("Start...")
                    self.program["interface"] = Interface.Interface(self.interfacelink)
                    self.program["interface"].running = True
                    self.program["interface"].start()
                    print("Interface ON")
                    cmd.start()
                else:
                    print("Interface is already running")
            elif command == "stop firewall":
                if self.program["firewall"].is_alive():
                    print("Shutdown...")
                    self.program["firewall"].running = False
                    self.program["firewall"].join()
                    print("Firewall OFF")
                    self.program["firewall"] = Sniffer.sniffer(self.interfacelink, self.cmdlink)
                else:
                    print("Firewall is already shutdown")
            elif command == "stop interface":
                if self.program["interface"].is_alive():
                    print("Shutdown...")
                    self.program["interface"].running = False
                    self.program["interface"].join()
                    print("Interface OFF")
                else:
                    print("Interface is already shutdown")
            elif command == "show rules":
                configuration = Filter.loadconf()
                for rules in configuration:
                    print(" ", configuration.index(rules) + 1, "- ", end="")
                    for rule in rules:
                        print(rule, ":", rules[rule], end=" | ")
                    print("")
            elif command[0:8] == "add rule":
                if re.match("^([a-z]+: ([a-z]|[A-Z]|[0-9]|[.])+, )*[a-z]+: ([a-z]|[A-Z]|[0-9]|[.])+$", command[9:]) != None:
                    file = open("FirewallARC.conf", "a")
                    file.write(command[9:] + "\n")
                    file.close()
                    print("Done")
                else:
                    print("Pattern for the new rule proprieties not correct", command[9:])
            elif command[0:11] == "delete rule":
                configuration = Filter.loadconf()
                try:
                    configuration.pop(int(command[12:]) - 1)
                    capturesave = ""
                    for rules in configuration:
                        for rule in rules:
                            if rule != "action" and rule != "id" and rules[rule] != "":
                                capturesave += str(rule) + ": " + str(rules[rule]) + ", "
                        capturesave = capturesave[0:-2] + "\n"
                    capturefile = open("FirewallARC.conf", "w")
                    capturefile.write(capturesave)
                    capturefile.close()
                    print("Done")
                except:
                    print("Invalid rule index")
            elif command[:9] == "read file":
                try:
                    Interface.rdpcap(command[10:]).summary()
                except:
                    print("Wrong type detected. Please select a pcap file.")
            elif command[0:3] == "ban":
                try:
                    file = open("FirewallARC.conf", "a")
                    file.write("ipsrc: " + socket.gethostbyname(command[4:]) + "\n")
                    file.close()
                    print("Done.")
                except:
                    print("Hostname not found")
            elif command == "unbanAll":
                check_file = os.path.getsize("FirewallARC.conf")
                if check_file == 0:
                    print("There is no IP to unban.")
                else:
                    print("Unbanning all IP without exception!")
                    with open("FirewallARC.conf", "w") as f:
                        f.write("")
                        f.close()
                    print("Done.")
            elif command[0:5] == "unban":
                try:
                    ip = socket.gethostbyname(command[6:])
                    configuration = Filter.loadconf()
                    for rules in configuration:
                        if len(rules) == 1 and "ipsrc" in rules and rules["ipsrc"] == ip:
                            configuration.pop(configuration.index(rules))
                    capturesave = ""
                    for rules in configuration:
                        for rule in rules:
                            if rule != "action" and rule != "id" and rules[rule] != "":
                                capturesave += str(rule) + ": " + str(rules[rule]) + ", "
                        capturesave = capturesave[0:-2] + "\n"
                    capturefile = open("FirewallARC.conf", "w")
                    capturefile.write(capturesave)
                    capturefile.close()
                    print("Done.")
                except:
                    print("Hostname not found")
            elif command == "show status":
                print("- firewall", "ON" if self.program["firewall"].is_alive() else "OFF")
                print("- interface", "ON" if self.program["interface"].is_alive() else "OFF")
            elif command[0:12] == "show packets":
                index = 0
                if len(command) > 12 and not re.match("^([a-z]+: ([a-z]|[A-Z]|[0-9]|[.])+, )*[a-z]+: ([a-z]|[A-Z]|[0-9]|[.])+$", command[13:]):
                    print("Argument doesn't respect the pattern")
                for rules in self.cmdlink:
                    tmp = ""
                    for rule in rules:
                        tmp += rule + ": " + rules[rule] + " | "
                    if len(command) > 12 and re.match("^([a-z]+: ([a-z]|[A-Z]|[0-9]|[.])+, )*[a-z]+: ([a-z]|[A-Z]|[0-9]|[.])+$", command[13:]):
                        myrules = command[13:].split(", ")
                        show = True
                        for myrule in myrules:
                            if myrule not in tmp:
                                show = False
                        if show:
                            index += 1
                            print(" ", index, "- ", end="")
                            print(tmp)
                    elif len(command) < 13:
                        index += 1
                        print(" ", index, "- ", end="")
                        print(tmp)
            elif command == "exit":
                running = False
                print("Shutdown interface...")
                if self.program["interface"].is_alive():
                    self.program["interface"].running = False
                    self.program["interface"].join()
                print("Interface OFF")
                print("Shutdown firewall...")
                if self.program["firewall"].is_alive():
                    self.program["firewall"].running = False
                    self.program["firewall"].join()
                print("Firewall OFF")
            elif command == "help":
                print("- start (auto start all)\n"
                      "- start only firewall\n"
                      "- start only interface\n"
                      "- stop firewall\n"
                      "- stop interface\n"
                      "- ban <host name>\n"
                      "- unban <host name>\n"
                      "- add rule <rule.s>\n"
                      "- delete rule <index>\n"
                      "- read file <path>\n"
                      "- help\n"
                      "- show rules\n"
                      "- show status\n"
                      "- show packets (<rule: value, rule: value...>)\n"
                      "- unbanAll\n"
                      "- exit")
            else:
                print("Unknown command. Use *help* command.")


firewall = Firewall()
firewall.run()
