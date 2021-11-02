# imports
import zulip
import time
from datetime import datetime
import os
import sys
from chatterbot import ChatBot
from chatterbot.trainers import ChatterBotCorpusTrainer
from configparser import ConfigParser
import validators
import tldextract
import ipaddress

# core modules
from modules import enumerator
from modules import scanner
from modules import monitor

# colors
BLUE = '\033[94m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CLEAR = '\x1b[0m'

# configs
try:
    conf = "configs/kenzer.conf"
    config = ConfigParser()
    with open(conf) as f:
        config.read_file(f, conf)
    _BotMail = config.get("kenzer", "email")
    _Site = config.get("kenzer", "site")
    _APIKey = config.get("kenzer", "key")
    _uploads = config.get("kenzer", "uploads")
    _subscribe = config.get("kenzer", "subscribe")
    _kenzer = config.get("kenzer", "path")
    _logging = config.get("kenzer", "logging")
    _splitting = config.get("kenzer", "splitting")
    _sync = config.get("kenzer", "syncing")
    _kenzerdb = config.get("kenzerdb", "path")
    _github = config.get("kenzerdb", "token")
    _repo = config.get("kenzerdb", "repo")
    _user = config.get("kenzerdb", "user")
    _home = config.get("env", "home")
    _greynoise = config.get("env", "greynoise")
    os.chdir(_kenzer)
    os.environ["HOME"] = _home
    if(os.path.exists(_kenzerdb) == False):
        os.system("mkdir "+_kenzerdb)
except:
    sys.exit(RED+"[!] invalid configurations"+CLEAR)

# kenzer


class Kenzer(object):

    # initializations
    def __init__(self):
        print(BLUE+"KENZER[3.29] by ARPSyndicate"+CLEAR)
        print(YELLOW+"automated web assets enumeration & scanning"+CLEAR)
        self.client = zulip.Client(email=_BotMail, site=_Site, api_key=_APIKey)
        self.upload = False
        if _subscribe == "True":
            self.subscribe()
            print(YELLOW+"[*] subscribed all streams"+CLEAR)
        if _uploads == "True":
            self.upload = True
            print(YELLOW+"[*] enabled uploads"+CLEAR)
        print(YELLOW+"[*] training chatterbot"+CLEAR)
        self.chatbot = ChatBot("Kenzer")
        self.trainer = ChatterBotCorpusTrainer(self.chatbot)
        time.sleep(2)
        self.trainer.train("chatterbot.corpus.english")
        time.sleep(2)
        self.modules = ["monitor", "program", "blacklist", "whitelist", "subenum", "repenum", "webenum", "servenum", "urlheadenum", "headenum", "socenum", "conenum", "dnsenum", "portenum", "asnenum", "urlenum", "favscan",
                        "cscan", "idscan", "subscan", "cvescan", "vulnscan", "portscan", "urlcvescan", "urlvulnscan", "endscan", "buckscan", "vizscan", "enum", "scan", "recon", "hunt", "sync", "freaker"]
        print(YELLOW+"[*] KENZER is online"+CLEAR)
        print(
            YELLOW+"[*] {0} modules up & running".format(len(self.modules))+CLEAR)

    # subscribes to all streams
    def subscribe(self):
        try:
            json = self.client.get_streams()["streams"]
            streams = [{"name": stream["name"]} for stream in json]
            self.client.add_subscriptions(streams)
        except:
            print(RED+"[!] an exception occurred.... retrying...."+CLEAR)
            self.subscribe()

    # manual
    def man(self):
        message = "**KENZER[3.29]**\n"
        message += "**KENZER modules**\n"
        message += "`blacklist <target>,<regex>` - initializes & removes blacklisted targets\n"
        message += "`whitelist <target>,<regex>` - initializes & keeps only whitelisted targets\n"
        message += "`program <target>,<link>` - initializes the program to which target belongs\n"
        message += "`subenum <target>` - enumerates subdomains\n"
        message += "`repenum <target>` - enumerates reputation of subdomains\n"
        message += "`portenum <target>` - enumerates open ports\n"
        message += "`servenum <target>` - enumerates services\n"
        message += "`webenum <target>` - enumerates webservers\n"
        message += "`headenum <target>` - enumerates additional info from webservers\n"
        message += "`urlheadenum <target>` - enumerates additional info from urls\n"
        message += "`asnenum <target>` - enumerates asn records\n"
        message += "`dnsenum <target>` - enumerates dns records\n"
        message += "`conenum <target>` - enumerates hidden files & directories\n"
        message += "`urlenum <target>` - enumerates urls\n"
        message += "`socenum <target>` - enumerates social media accounts\n"
        message += "`subscan <target>` - hunts for subdomain takeovers\n"
        message += "`cscan[-<severity>] <target>` - scan with customized templates\n"
        message += "`cvescan[-<severity>] <target>` - hunts for CVEs\n"
        message += "`vulnscan[-<severity>] <target>` - hunts for other common vulnerabilites\n"
        message += "`urlcvescan[-<severity>] <target>` - hunts for CVEs in URLs\n"
        message += "`urlvulnscan[-<severity>] <target>` - hunts for other common vulnerabilites in URLs\n"
        message += "`endscan[-<severity>] <target>` - hunts for vulnerablities in custom endpoints\n"
        message += "`idscan[-<severity>] <target>` - identifies applications running on webservers\n"
        message += "`portscan <target>` - scans open ports\n"
        message += "`buckscan <target>` - hunts for unreferenced aws s3 buckets\n"
        message += "`favscan <target>` - fingerprints webservers using favicon\n"
        message += "`vizscan <target>` - screenshots applications running on webservers\n"
        message += "`enum <target>` - runs all enumerator modules\n"
        message += "`scan <target>` - runs all scanner modules\n"
        message += "`recon <target>` - runs all modules\n"
        message += "`hunt <target>` - runs your custom workflow\n"
        message += "`upload` - switches upload functionality\n"
        message += "`upgrade` - upgrades kenzer to latest version\n"
        message += "`monitor` - monitors ct logs for new subdomains\n"
        message += "`monitor normalize` - normalizes the enumerations from ct logs\n"
        message += "`monitor db` - monitors ct logs for domains in summary/domain.txt\n"
        message += "`monitor autohunt <frequency(default=5)>` - starts automated hunt while monitoring\n"
        message += "`sync` - synchronizes the local kenzerdb with github\n"
        message += "`freaker <module>` - runs freaker module\n"
        message += "`kenzer <module>` - runs a specific module\n"
        message += "`kenzer man` - shows this manual\n"
        message += "or you can just interact with chatterbot\n"
        self.sendMessage(message)
        return

    # sends messages
    def sendMessage(self, message):
        time.sleep(2)
        if self.type == "private":
            self.client.send_message({
                "type": self.type,
                "to": self.sender_email,
                "content": message
            })
        else:
            self.client.send_message({
                "type": self.type,
                "subject": self.subject,
                "to": self.display_recipient,
                "content": message
            })
        time.sleep(2)
        return

    # uploads output
    def uploader(self, domain, raw):
        global _kenzerdb
        global _Site
        org = domain
        data = _kenzerdb+org+"/"+raw
        if(os.path.exists(data) == False):
            return
        with open(data, 'rb') as fp:
            uploaded = self.client.call_endpoint(
                'user_uploads',
                method='POST',
                files=[fp],
            )
        self.sendMessage("{0}/{1} : {3}{2}".format(org,
                                                   raw, uploaded['uri'], _Site))
        return

    # removes log files
    def remlog(self, cont):
        dtype = False
        if validators.domain(cont.lower()) == True or cont.lower() == "monitor":
            dtype = True
        else:
            try:
                ipaddress.ip_network(cont)
            except ValueError:
                return
        self.enum = enumerator.Enumerator(
            cont.lower(), _kenzerdb, _kenzer, dtype)
        message = self.enum.remlog()
        return

    # splits .kenz files
    def splitkenz(self, cont):
        dtype = False
        if validators.domain(cont.lower()) == True or cont.lower() == "monitor":
            dtype = True
        else:
            try:
                ipaddress.ip_network(cont)
            except ValueError:
                return
        self.enum = enumerator.Enumerator(
            cont.lower(), _kenzerdb, _kenzer, dtype)
        message = self.enum.splitkenz()
        return

    # merges .kenz files
    def mergekenz(self, cont):
        dtype = False
        if validators.domain(cont.lower()) == True or cont.lower() == "monitor":
            dtype = True
        else:
            try:
                ipaddress.ip_network(cont)
            except ValueError:
                return
        self.enum = enumerator.Enumerator(
            cont.lower(), _kenzerdb, _kenzer, dtype)
        message = self.enum.mergekenz()
        return

    # monitors ct logs
    def monitor(self):
        self.sendMessage("[monitoring]")
        self.monitor = monitor.Monitor(_kenzerdb, " ".join(self.content[2:]))
        self.monitor.certex()
        return

    # monitors ct logs for domains in summary/domain.txt
    def monitor_kenzerdb(self):
        domfile = _kenzerdb+"../summary/domain.txt"
        with open(domfile) as f:
            line = len(f.readlines())
        self.sendMessage("[monitoring]")
        self.monitor = monitor.Monitor(_kenzerdb)
        self.monitor.certex()
        return

    # starts automated hunt while monitoring
    def monitor_autohunt(self, freq=5):
        i = 1
        while i <= freq:
            self.monitor = monitor.Monitor(_kenzerdb)
            self.content = "**{0}** hunt monitor".format(
                _BotMail.split("@")[0]).split()
            self.hunt()
            self.monitor.normalize()
            self.sendMessage(
                "[autohunt - ({0}%)]".format(int(i/freq*100)))
            if _sync == "True":
                self.sync()
            i = i+1
        return

    # normalizes enumerations from ct logs
    def normalize(self):
        self.monitor = monitor.Monitor(_kenzerdb, " ".join(self.content[2:]))
        self.monitor.normalize()
        self.sendMessage("[normalized]")
        return

    # initializes the program to which target belongs
    def program(self):
        for i in range(2, len(self.content)):
            dtype = False
            domain = self.content[i].split(",")[0].lower()
            if validators.domain(domain) == True or domain == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(domain)
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[program - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, dtype)
            message = self.enum.program(
                self.content[i].split(",")[1])
            self.sendMessage(
                "[program - ({0}%) - {1}] {2}".format(int((i-1)/(len(self.content)-2)*100), message, domain))
            if self.upload:
                file = "program.kenz"
                self.uploader(self.content[i], file)
        return

    # initializes & removes blacklisted targets
    def blacklist(self):
        for i in range(2, len(self.content)):
            dtype = True
            domain = self.content[i].split(",")[0].lower()
            if(validators.domain(domain) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[blacklist - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, dtype)
            message = self.enum.blacklist(
                self.content[i].split(",")[1])
            self.sendMessage(
                "[blacklist - ({0}%) - {1}] {2}".format(int((i-1)/(len(self.content)-2)*100), message, domain))
            if self.upload:
                file = "blacklist.kenz"
                self.uploader(self.content[i], file)
        return

    # initializes & keeps only whitelisted targets
    def whitelist(self):
        for i in range(2, len(self.content)):
            dtype = True
            domain = self.content[i].split(",")[0].lower()
            if(validators.domain(domain) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[whitelist - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, dtype)
            message = self.enum.whitelist(
                self.content[i].split(",")[1])
            self.sendMessage(
                "[whitelist - ({0}%) - {1}] {2}".format(int((i-1)/(len(self.content)-2)*100), message, domain))
            if self.upload:
                file = "whitelist.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates subdomains
    def subenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if validators.domain(self.content[i].lower()) != True and self.content[i].lower() != "monitor":
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[subenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            if self.content[i].lower() == "monitor":
                self.monitor = monitor.Monitor(_kenzerdb)
                self.monitor.initialize()
                message = self.monitor.subenum()
            else:
                self.enum = enumerator.Enumerator(
                    self.content[i].lower(), _kenzerdb, _kenzer, dtype)
                self.mergekenz(self.content[i].lower())
                message = self.enum.subenum()
            self.sendMessage("[subenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "subenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # probes services from enumerated ports
    def servenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[servenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.servenum()
            self.sendMessage("[servenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "servenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # probes web servers from enumerated ports
    def webenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[webenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.webenum()
            self.sendMessage("[webenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "webenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates additional info from webservers
    def headenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[headenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.headenum()
            self.sendMessage("[headenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "headenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates additional info from urls
    def urlheadenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage("[urlheadenum - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.urlheadenum()
            self.sendMessage("[urlheadenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "urlheadenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates dns records
    def dnsenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True and self.content[i].lower() != "monitor"):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[dnsenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.dnsenum()
            self.sendMessage("[dnsenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "dnsenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates hidden files & directories
    def conenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True and self.content[i].lower() != "monitor"):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[conenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.conenum()
            self.sendMessage(
                "[conenum - ({0}%) - {1}] {2}".format(int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "conenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates asn for enumerated subdomains
    def asnenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True and self.content[i].lower() != "monitor"):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[asnenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.asnenum()
            self.sendMessage("[asnenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "asnenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates open ports
    def portenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[portenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.portenum()
            self.sendMessage("[portenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "portenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates reputation of subdomains
    def repenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[repenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.repenum(_greynoise)
            self.sendMessage("[repenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "repenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates urls
    def urlenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[urlenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.urlenum(_github)
            self.sendMessage("[urlenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "urlenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # hunts for subdomain takeovers
    def subscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[subscan - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            self.mergekenz(self.content[i].lower())
            message = self.scan.subscan()
            self.sendMessage("[subscan - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "subscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates social media accounts
    def socenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[socenum - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.socenum()
            self.sendMessage("[socenum - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "socenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # scans with customized templates
    def cscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[cscan{2} - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.cscan()
            self.sendMessage("[cscan{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "cscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # hunts for CVEs
    def cvescan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[cvescan{2} - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.cvescan()
            self.sendMessage("[cvescan{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "cvescan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # hunts for other common vulnerabilities
    def vulnscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[vulnscan{2} - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.vulnscan()
            self.sendMessage("[vulnscan{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "vulnscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # hunts for CVEs in URLs
    def urlcvescan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[urlcvescan{2} - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.urlcvescan()
            self.sendMessage("[urlcvescan{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "urlcvescan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # hunts for other common vulnerabilities in URLs
    def urlvulnscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[urlvulnscan{2} - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.urlvulnscan()
            self.sendMessage("[urlvulnscan{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "urlvulnscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # scans open ports
    def portscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[portscan - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            message = self.scan.portscan()
            self.sendMessage(
                "[portscan - ({0}%) ~] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            if self.upload:
                file = "portscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
        return

    # hunts for vulnerablities in custom endpoints
    def endscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[endscan{2} - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.endscan()
            self.sendMessage("[endscan{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "endscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # hunts for subdomain takeovers
    def buckscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[buckscan - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            self.mergekenz(self.content[i].lower())
            message = self.scan.buckscan()
            self.sendMessage("[buckscan - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "buckscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # fingerprints servers using favicons
    def favscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[favscan - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            self.mergekenz(self.content[i].lower())
            message = self.scan.favscan()
            self.sendMessage("[favscan - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower()))
            if self.upload:
                file = "favscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # identifies applications running on webservers
    def idscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[idscan{2} - ({0}%)] {1}".format(
                int((i-1)/(len(self.content)-2)*100), self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.idscan()
            self.sendMessage("[idscan{3} - ({0}%) - {1}] {2}".format(
                int((i-1)/(len(self.content)-2)*100), message, self.content[i].lower(), display))
            if self.upload:
                file = "idscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # screenshots applications running on webservers
    def vizscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[vizscan - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            message = self.scan.vizscan()
            self.sendMessage(
                "[vizscan - ({0}%) ~] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i].lower()))
            if self.upload:
                for file in os.listdir(_kenzerdb+self.content[i].lower()+"/aquatone/screenshots/"):
                    self.uploader(self.content[i],
                                  "aquatone/screenshots/"+file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
        return

    # runs all enumeration modules
    def enumall(self):
        self.subenum()
        self.asnenum()
        self.portenum()
        self.servenum()
        self.webenum()
        self.headenum()
        self.dnsenum()
        self.socenum()
        self.conenum()
        # experimental ones
        # self.repenum()
        # self.urlenum()
        # self.urlheadenum()
        return

    # runs all scanning modules
    def scanall(self):
        self.favscan()
        self.idscan()
        self.subscan()
        self.buckscan()
        self.cvescan()
        self.vulnscan()
        self.vizscan()
        self.portscan()
        # experimental ones
        # self.urlcvescan()
        # self.urlvulnscan()
        # self.endscan()
        return

    # define your custom workflow
    def hunt(self):
        self.subenum()
        self.asnenum()
        self.portenum()
        self.servenum()
        self.webenum()
        self.headenum()
        self.dnsenum()
        self.subscan()
        self.idscan()
        self.favscan()
        self.buckscan()
        self.cvescan()
        self.vulnscan()
        # experimental ones
        # self.conenum()
        # self.repenum()
        # self.socenum()
        # self.portscan()
        # self.vizscan()
        # self.urlenum()
        # self.urlheadenum()
        # self.urlcvescan()
        # self.urlvulnscan()
        # self.endscan()
        return

    # runs all modules
    def recon(self):
        self.enumall()
        self.scanall()
        return
    
    # runs freaker module
    def freaker(self):
        for i in range(2, len(self.content)):
            os.system("freaker -c {0} -r {1}".format("configs/freaker.yaml", self.content[i]))
            self.sendMessage(
                "[freaker - ({0}%)] {1}".format(int((i-1)/(len(self.content)-2)*100), self.content[i]))

    # synchronizes the local kenzerdb with github
    def sync(self):
        os.system("cd {0} && git remote set-url origin https://{1}@github.com/{2}/{3}.git && git pull && cd ../scripts && bash remove_logs.sh && bash generate.sh && cd .. && git add . && git commit -m \"{4}\" && git push".format(
            _kenzerdb, _github, _user, _repo, _BotMail+"("+str(datetime.utcnow())+")"))
        self.sendMessage("[synced]")
        return

    # upgrades kenzer to latest version
    def upgrade(self):
        os.system("bash update.sh")
        self.sendMessage("[upgraded]")
        return

    # controls
    def process(self, text):
        self.content = text["content"].split()
        self.sender_email = text["sender_email"]
        self.type = text["type"]
        self.display_recipient = text['display_recipient']
        self.subject = text['subject']
        content = self.content
        print(content)
        if self.sender_email == _BotMail:
            return
        try:
            if len(content) > 1 and content[0].lower() == "@**{0}**".format(_BotMail.split('@')[0].replace("-bot", "")):
                if content[1].lower() == "man":
                    if len(content) == 2:
                        self.man()
                    else:
                        message = "excuse me???"
                        self.sendMessage(message)
                elif content[1].lower() == "monitor":
                    if content[2].lower() == "normalize":
                        self.normalize()
                    elif content[2].lower() == "db":
                        self.monitor_kenzerdb()
                    elif content[2].lower() == "autohunt":
                        if len(content) == 4:
                            self.monitor_autohunt(int(content[3]))
                        else:
                            self.monitor_autohunt()
                    else:
                        self.monitor()
                elif content[1].lower() == "blacklist":
                    self.blacklist()
                elif content[1].lower() == "whitelist":
                    self.whitelist()
                elif content[1].lower() == "program":
                    self.program()
                elif content[1].lower() == "subenum":
                    self.subenum()
                elif content[1].lower() == "repenum":
                    self.repenum()
                elif content[1].lower() == "webenum":
                    self.webenum()
                elif content[1].lower() == "servenum":
                    self.servenum()
                elif content[1].lower() == "socenum":
                    self.socenum()
                elif content[1].lower() == "headenum":
                    self.headenum()
                elif content[1].lower() == "urlheadenum":
                    self.urlheadenum()
                elif content[1].lower() == "asnenum":
                    self.asnenum()
                elif content[1].lower() == "dnsenum":
                    self.dnsenum()
                elif content[1].lower() == "conenum":
                    self.conenum()
                elif content[1].lower() == "favscan":
                    self.favscan()
                elif content[1].lower() == "portenum":
                    self.portenum()
                elif content[1].lower() == "urlenum":
                    self.urlenum()
                elif content[1].lower() == "subscan":
                    self.subscan()
                elif content[1].split("-")[0].lower() == "cscan":
                    if len(content[1].split("-")) > 1:
                        self.cscan(content[1].split("-")[1].lower())
                    else:
                        self.cscan()
                elif content[1].split("-")[0].lower() == "cvescan":
                    if len(content[1].split("-")) > 1:
                        self.cvescan(content[1].split("-")[1].lower())
                    else:
                        self.cvescan()
                elif content[1].split("-")[0].lower() == "vulnscan":
                    if len(content[1].split("-")) > 1:
                        self.vulnscan(content[1].split("-")[1].lower())
                    else:
                        self.vulnscan()
                elif content[1].split("-")[0].lower() == "urlcvescan":
                    if len(content[1].split("-")) > 1:
                        self.urlcvescan(content[1].split("-")[1].lower())
                    else:
                        self.urlcvescan()
                elif content[1].split("-")[0].lower() == "urlvulnscan":
                    if len(content[1].split("-")) > 1:
                        self.urlvulnscan(content[1].split("-")[1].lower())
                    else:
                        self.urlvulnscan()
                elif content[1].lower() == "portscan":
                    self.portscan()
                elif content[1].split("-")[0].lower() == "endscan":
                    if len(content[1].split("-")) > 1:
                        self.endscan(content[1].split("-")[1].lower())
                    else:
                        self.endscan()
                elif content[1].split("-")[0].lower() == "idscan":
                    if len(content[1].split("-")) > 1:
                        self.idscan(content[1].split("-")[1].lower())
                    else:
                        self.idscan()
                elif content[1].lower() == "vizscan":
                    self.vizscan()
                elif content[1].lower() == "buckscan":
                    self.buckscan()
                elif content[1].lower() == "enum":
                    self.enumall()
                elif content[1].lower() == "scan":
                    self.scanall()
                elif content[1].lower() == "hunt":
                    self.hunt()
                elif content[1].lower() == "recon":
                    self.recon()
                elif content[1].lower() == "sync":
                    self.sync()
                elif content[1].lower() == "freaker":
                    self.freaker()
                elif content[1].lower() == "upgrade":
                    self.upgrade()
                elif content[1].lower() == "upload":
                    self.upload = not self.upload
                    self.sendMessage("upload: "+str(self.upload))
                else:
                    message = self.chatbot.get_response(' '.join(self.content))
                    message = message.serialize()['text']
                    self.sendMessage(message)
        except Exception as exception:
            self.sendMessage("[exception] {0}:{1}".format(
                type(exception).__name__, str(exception)))
            print(exception.__class__.__name__ + ": " + str(exception))
        return

# main


def main():
    bot = Kenzer()
    bot.client.call_on_each_message(bot.process)


# runs main
if __name__ == "__main__":
    main()
