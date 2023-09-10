import pygame, re
from easygui import fileopenbox, filesavebox, msgbox
from scapy.all import rdpcap
from Filter import loadconf, Packet
from threading import Thread


class Interface(Thread):
    """User Interface"""

    running = True

    def __init__(self, link: list):
        Thread.__init__(self)
        self.__link = link
        self.__scanning = True
        self.__mode = "read"
        self.__info = []
        self.__link.clear()
        self.__minrule = 0
        self.__case = [False, 0, 0]
    
    def loadfile(self):  # load a pcap or .txt file if it's possible
        fileload = fileopenbox("", "Choose a capture file")
        try:
            if fileload[-4:] == ".txt":
                for element in loadconf(fileload):
                    self.__info.append(Packet(element))
            else:
                for element in rdpcap(fileload).sessions():
                    element += " "
                    step = 0
                    tmp = ""
                    myinfo = dict()
                    myinfo["ipsrc"] = ""
                    myinfo["ipdest"] = ""
                    for i in range(len(element)):
                        if element[i] == " ":
                            if step == 0:
                                myinfo["protocol"] = tmp
                            elif step == 1:
                                if myinfo["protocol"] != "ARP" and myinfo["protocol"] != "IP":
                                    myinfo["portsrc"] = tmp
                                else:
                                    myinfo["ipsrc"] += tmp
                            elif step == 3:
                                if myinfo["protocol"] != "ARP" and myinfo["protocol"] != "IP":
                                    myinfo["portdest"] = tmp
                                else:
                                    myinfo["ipdest"] += tmp
                            step += 1
                            tmp = ""
                        else:
                            if element[i] == ":":
                                if step == 1:
                                    myinfo["ipsrc"] += tmp + ":"
                                elif step == 3:
                                    myinfo["ipdest"] += tmp + ":"
                                tmp = ""
                            else:
                                tmp += element[i]
                    if myinfo["protocol"] != "ARP" and myinfo["protocol"] != "IP":
                        myinfo["ipsrc"] = myinfo["ipsrc"][:-1]
                        myinfo["ipdest"] = myinfo["ipdest"][:-1]
                    self.__info.append(Packet(myinfo))
                    myinfo.clear()
        except:
            msgbox("Wrong type detected. Please select a pcap file.", "Error")

    def savefile(self, info):  # save a capture file type text to load it later. /!\ NOT A .CAP FILE
        capturesave = ""
        for element in info:
            if element.isempty():
                continue
            for rule in element.getall():
                if rule != "action" and rule != "id" and element.getinfo(rule) != "":
                    capturesave += str(rule) + ": " + str(element.getinfo(rule)) + ", "
            capturesave = capturesave[0:-2] + "\n"
        try:
            if self.__mode == "conf":
                filename = "FirewallARC.conf"
            else:
                filename = filesavebox("Save file")
                if filename[-4:] != ".txt":
                    filename += ".txt"
            capturefile = open(filename, "w")
            capturefile.write(capturesave)
            capturefile.close()
        except:
            print("Error : impossible to save")

    def static_pre_event(self, mysurface):  # print static element pre-event on the interface
        pygame.draw.rect(mysurface, (0, 0, 0), (0, 75, 1000, 400))
        pygame.draw.rect(mysurface, (50, 50, 50), (0, 0, 1000, 25))
        pygame.draw.rect(mysurface, (50, 50, 50), (0, 50, 1000, 25))
        pygame.draw.rect(mysurface, (50, 50, 50), (0, 475, 1000, 25))
        mousse = pygame.mouse.get_pos()
        if 10 < mousse[0] <= 35 and 0 < mousse[1] <= 25:
            pygame.draw.rect(mysurface, (100, 100, 100), (10, 0, 25, 25))
        elif 45 < mousse[0] <= 70 and 0 < mousse[1] <= 25:
            pygame.draw.rect(mysurface, (100, 100, 100), (45, 0, 25, 25))
        elif 80 < mousse[0] <= 105 and 0 < mousse[1] <= 25:
            pygame.draw.rect(mysurface, (100, 100, 100), (80, 0, 25, 25))
        elif 115 < mousse[0] <= 140 and 0 < mousse[1] <= 25:
            pygame.draw.rect(mysurface, (100, 100, 100), (115, 0, 25, 25))
        elif 150 < mousse[0] <= 175 and 0 < mousse[1] <= 25:
            pygame.draw.rect(mysurface, (100, 100, 100), (150, 0, 25, 25))
        elif 185 < mousse[0] <= 210 and 0 < mousse[1] <= 25:
            pygame.draw.rect(mysurface, (100, 100, 100), (185, 0, 25, 25))
        elif 75 < mousse[1] <= 465 and round((mousse[1] - 7) / 15) - 5 < len(self.__info):
            if self.__mode == "read":
                # print("y")
                pygame.draw.rect(mysurface, (100, 100, 100), (0, round((mousse[1] - 7) / 15) * 15 + 2, 1000, 15))
            elif self.__mode == "conf":
                if 50 < mousse[0] < 250:
                    pygame.draw.rect(mysurface, (100, 100, 100), (50, round((mousse[1] - 7) / 15) * 15 + 2, 200, 15))
                elif 250 < mousse[0] < 450:
                    pygame.draw.rect(mysurface, (100, 100, 100), (250, round((mousse[1] - 7) / 15) * 15 + 2, 200, 15))
                elif 450 < mousse[0] < 600:
                    pygame.draw.rect(mysurface, (100, 100, 100), (450, round((mousse[1] - 7) / 15) * 15 + 2, 150, 15))
                elif 600 < mousse[0] < 750:
                    pygame.draw.rect(mysurface, (100, 100, 100), (600, round((mousse[1] - 7) / 15) * 15 + 2, 150, 15))
                elif 750 < mousse[0] < 900:
                    pygame.draw.rect(mysurface, (100, 100, 100), (750, round((mousse[1] - 7) / 15) * 15 + 2, 150, 15))
        elif 50 < mousse[1] <= 75:
            pygame.draw.rect(mysurface, (100, 100, 100), (0, 50, 1000, 25))
        elif 475 < mousse[1] <= 500:
            pygame.draw.rect(mysurface, (100, 100, 100), (0, 475, 1000, 25))

    def static_post_event(self, mysurface, police):  # print static element post-event on the interface
        mysurface.blit(police[20].render("↑", True, (255, 255, 255), None), (480, 55))
        mysurface.blit(police[20].render("↓", True, (255, 255, 255), None), (480, 480))
        for i in range(26):
            if len(self.__info) > i + self.__minrule:
                try:
                    mysurface.blit(police[10].render(self.__info[i + self.__minrule].getid(), True, (255, 255, 255), None), (5, i * 15 + 80))
                    mysurface.blit(police[10].render(self.__info[i + self.__minrule].getinfo("ipsrc"), True, (255, 255, 255), None), (55, i * 15 + 80))
                    mysurface.blit(police[10].render(self.__info[i + self.__minrule].getinfo("ipdest"), True, (255, 255, 255), None), (255, i * 15 + 80))
                    mysurface.blit(police[10].render(self.__info[i + self.__minrule].getinfo("protocol"), True, (255, 255, 255), None), (455, i * 15 + 80))
                    mysurface.blit(police[10].render(self.__info[i + self.__minrule].getinfo("portsrc"), True, (255, 255, 255), None), (605, i * 15 + 80))
                    mysurface.blit(police[10].render(self.__info[i + self.__minrule].getinfo("portdest"), True, (255, 255, 255), None), (755, i * 15 + 80))
                    mysurface.blit(police[10].render("Accepted" if self.__info[i + self.__minrule].getinfo("action") and self.__mode == "read" else "Droped", True, (0, 255, 0) if self.__info[i + self.__minrule].getinfo("action") and self.__mode == "read" else (255, 0, 0), None), (905, i * 15 + 80))
                    # print(self.__info[i + self.__minrule].getinfo("action"))
                except AttributeError as ex: 
                    print(ex)

    def print_icon(self, mysurface, play, pause, stop, save, file, edit):  # print the icon on the interface
        mysurface.blit(play, (10, 0))
        mysurface.blit(pause, (45, 0))
        mysurface.blit(stop, (80, 0))
        mysurface.blit(save, (115, 0))
        mysurface.blit(file, (150, 0))
        mysurface.blit(edit, (185, 0))

    def event_management(self, mysurface, police, play, pause, stop, save, file, edit):  # management of the pygame event
        mousse = pygame.mouse.get_pos()
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                self.running = False
            elif event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:  # click of the mouse
                self.__case[0] = False
                if 50 < mousse[1] <= 75:
                    self.__minrule -= 1 if self.__minrule > 0 else 0
                elif 475 < mousse[1] <= 500:
                    self.__minrule += 1 if self.__minrule < len(self.__info) - 26 else 0
                elif 10 < mousse[0] <= 35 and 0 < mousse[1] <= 25:  # Play button
                    self.__link.clear()
                    self.__scanning = True
                    if self.__mode == "conf":
                        self.__mode = "read"
                        self.__info.clear()
                        Packet.index = 0
                elif 45 < mousse[0] <= 70 and 0 < mousse[1] <= 25:  # Pause button
                    self.__scanning = False
                elif 80 < mousse[0] <= 105 and 0 < mousse[1] <= 25:  # Stop button
                    self.__scanning = False
                    self.__info.clear()
                    Packet.index = 0
                    self.__minrule = 0
                    self.__mode = "read"
                elif 115 < mousse[0] <= 140 and 0 < mousse[1] <= 25:  # Save buttonf
                    self.savefile(self.__info)
                elif 150 < mousse[0] <= 175 and 0 < mousse[1] <= 25:  # Load button
                    self.__info.clear()
                    self.__scanning = False
                    Packet.index = 0
                    self.__minrule = 0
                    self.__mode = "read"
                    pygame.display.set_caption("Firewall File Reader Loading...")
                    self.print_icon(mysurface, play, pause, stop, save, file, edit)
                    mysurface.blit(police[20].render("↑", True, (255, 255, 255), None), (480, 55))
                    mysurface.blit(police[20].render("↓", True, (255, 255, 255), None), (480, 480))
                    pygame.display.flip()
                    self.loadfile()
                elif 185 < mousse[0] <= 210 and 0 < mousse[1] <= 25:  # Edit button
                    self.__mode = "conf"
                    self.__info.clear()
                    Packet.index = 0
                    self.__minrule = 0
                    self.__scanning = False
                    for element in loadconf():
                        self.__info.append(Packet(element))
                    for i in range(27):
                        self.__info.append(Packet({}))
                elif self.__mode == "conf" and round((mousse[1] - 7) / 15) - 5 < len(self.__info):  # edit rules screen
                    if 50 < mousse[0] < 250 and 75 < mousse[1] <= 465:
                        self.__case = [True, 0, round((mousse[1] - 7) / 15) - 5, 50,
                                       round((mousse[1] - 7) / 15) * 15 + 2, 200]
                        pygame.draw.rect(mysurface, (200, 200, 200),
                                         (self.__case[3], self.__case[4], self.__case[5], 15))
                    elif 250 < mousse[0] < 450 and 75 < mousse[1] <= 465:
                        self.__case = [True, 1, round((mousse[1] - 7) / 15) - 5, 250,
                                       round((mousse[1] - 7) / 15) * 15 + 2, 200]
                        pygame.draw.rect(mysurface, (200, 200, 200),
                                         (self.__case[3], self.__case[4], self.__case[5], 15))
                    elif 450 < mousse[0] < 600 and 75 < mousse[1] <= 465:
                        self.__case = [True, 2, round((mousse[1] - 7) / 15) - 5, 450,
                                       round((mousse[1] - 7) / 15) * 15 + 2,
                                       150]
                        pygame.draw.rect(mysurface, (200, 200, 200),
                                         (self.__case[3], self.__case[4], self.__case[5], 15))
                    elif 600 < mousse[0] < 750 and 75 < mousse[1] <= 465:
                        self.__case = [True, 3, round((mousse[1] - 7) / 15) - 5, 600,
                                       round((mousse[1] - 7) / 15) * 15 + 2,
                                       150]
                        pygame.draw.rect(mysurface, (200, 200, 200),
                                         (self.__case[3], self.__case[4], self.__case[5], 15))
                    elif 750 < mousse[0] < 900 and 75 < mousse[1] <= 465:
                        self.__case = [True, 4, round((mousse[1] - 7) / 15) - 5, 750,
                                       round((mousse[1] - 7) / 15) * 15 + 2,
                                       150]
                        pygame.draw.rect(mysurface, (200, 200, 200),
                                         (self.__case[3], self.__case[4], self.__case[5], 15))
                    self.savefile(self.__info.copy())
            elif event.type == pygame.MOUSEBUTTONDOWN and event.button == 4:  # scroll up
                self.__minrule -= 100 if self.__minrule > 0 else 0
            elif event.type == pygame.MOUSEBUTTONDOWN and event.button == 5:  # scroll down
                if self.__mode == "conf":
                    self.__info.append(Packet({}))
                self.__minrule += 100 if self.__minrule < len(self.__info) - 26 else 0
            elif event.type == pygame.KEYDOWN and self.__mode == "conf" and event.key != pygame.K_RETURN:  # keyboard input management
                if event.key == pygame.K_BACKSPACE:
                    if self.__case[1] == 0:
                        self.__info[self.__case[2]].setinfo("ipsrc", self.__info[self.__case[2]].getinfo("ipsrc")[0:-1])
                    elif self.__case[1] == 1:
                        self.__info[self.__case[2]].setinfo("ipdest",
                                                            self.__info[self.__case[2]].getinfo("ipdest")[0:-1])
                    elif self.__case[1] == 2:
                        self.__info[self.__case[2]].setinfo("protocol",
                                                            self.__info[self.__case[2]].getinfo("protocol")[0:-1])
                    elif self.__case[1] == 3:
                        self.__info[self.__case[2]].setinfo("portsrc",
                                                            self.__info[self.__case[2]].getinfo("portsrc")[0:-1])
                    elif self.__case[1] == 4:
                        self.__info[self.__case[2]].setinfo("portdest",
                                                            self.__info[self.__case[2]].getinfo("portdest")[0:-1])
                else:
                    if self.__case[1] == 0:
                        self.__info[self.__case[2]].setinfo("ipsrc", self.__info[self.__case[2]].getinfo("ipsrc") + event.unicode)
                    elif self.__case[1] == 1:
                        self.__info[self.__case[2]].setinfo("ipdest", self.__info[self.__case[2]].getinfo("ipdest") + event.unicode)
                    elif self.__case[1] == 2:
                        self.__info[self.__case[2]].setinfo("protocol", self.__info[self.__case[2]].getinfo("protocol") + event.unicode)
                    elif self.__case[1] == 3:
                        self.__info[self.__case[2]].setinfo("portsrc", self.__info[self.__case[2]].getinfo("portsrc") + event.unicode)
                    elif self.__case[1] == 4:
                        self.__info[self.__case[2]].setinfo("portdest", self.__info[self.__case[2]].getinfo("portdest") + event.unicode)

    def run(self):
        pygame.init()
        icons = pygame.image.load("D:/donlod/FPF/Media/firewall_icon-icons.com_52836.ico")
        pygame.display.set_caption("Firewall Modified - iFanpS")
        pygame.display.set_icon(icons)
        mysurface = pygame.display.set_mode((1000, 500))
        pygame.draw.rect(mysurface, (0, 0, 0), (0, 25, 1000, 25))
        police = [pygame.font.Font("Media\Matrix.ttf", i) for i in range(1, 100)]
        play = pygame.image.load("Media\PlayBlanc.png").convert_alpha()
        pause = pygame.image.load("Media\PauseBlanc.png").convert_alpha()
        stop = pygame.image.load("Media\StopBlanc.png").convert_alpha()
        save = pygame.image.load("Media\SaveBlanc.png").convert_alpha()
        file = pygame.image.load("Media\FileBlanc.png").convert_alpha()
        edit = pygame.image.load("Media\EditBlanc.png").convert_alpha()
        mysurface.blit(police[15].render("ID", True, (255, 255, 255), None), (5, 32))
        mysurface.blit(police[15].render("IP SRC", True, (255, 255, 255), None), (55, 32))
        mysurface.blit(police[15].render("IP DST", True, (255, 255, 255), None), (255, 32))
        mysurface.blit(police[15].render("PROTOCOL", True, (255, 255, 255), None), (455, 32))
        mysurface.blit(police[15].render("PORT SRC", True, (255, 255, 255), None), (605, 32))
        mysurface.blit(police[15].render("PORT DST", True, (255, 255, 255), None), (755, 32))
        mysurface.blit(police[15].render("STATUS", True, (255, 255, 255), None), (905, 32))
        while self.running:
            if self.__scanning:
                for element in self.__link:
                    self.__info.append(Packet(element))
                    if self.__minrule == len(self.__info) - 27 and len(self.__info) >= 26:
                        self.__minrule += 1
                self.__link.clear()
            self.static_pre_event(mysurface)
            self.event_management(mysurface, police, play, pause, stop, save, file, edit)
            if self.__case[0]:
                pygame.draw.rect(mysurface, (200, 200, 200), (self.__case[3], self.__case[4], self.__case[5], 15))
            self.print_icon(mysurface, play, pause, stop, save, file, edit)
            self.static_post_event(mysurface, police)
            pygame.display.set_caption("Firewall Modified - iFanpS")
            pygame.display.flip()
            pygame.time.wait(20)
        pygame.quit()
