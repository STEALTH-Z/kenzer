# imports
import os

# enumerator


class Enumerator:

    # initializations
    def __init__(self, domain, db, kenzer, dtype):
        self.domain = domain
        self.organization = domain
        self.dtype = dtype
        if dtype:
            self.path = db+self.organization
        else:
            self.path = db+self.organization.replace("/", "#")
        self.resources = kenzer+"resources"
        self.templates = self.resources+"/kenzer-templates/"
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    # core enumerator modules

    # initializes the program to which target belongs
    def program(self, program=""):
        domain = self.domain
        path = self.path
        output = path+"/program.kenz"
        programs = []
        if(len(program) > 0):
            programs.append(program)
            if(os.path.exists(output)):
                with open(output, "r") as f:
                    programs.extend(f.read().splitlines())
                    programs = list(set(programs))
                    programs.sort()
                    f.close()
            with open(output, "w") as f:
                f.writelines("%s\n" % line for line in programs)
                f.close()
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # initializes & removes blacklisted targets
    def blacklist(self, blacklist=""):
        domain = self.domain
        path = self.path
        output = path+"/blacklist.kenz"
        files = []
        for x in os.listdir(path):
            if x.endswith(".kenz") and x not in ["blacklist.kenz", "whitelist.kenz", "program.kenz", "repoenum.kenz", "reposcan.kenz", "portscan.kenz", "vizscan.kenz"]:
                files.append(x)
        blacklists = []
        if(len(blacklist) > 0):
            blacklists.append(blacklist)
            if(os.path.exists(output)):
                with open(output, "r") as f:
                    blacklists.extend(f.read().splitlines())
                    blacklists = list(set(blacklists))
                    blacklists.sort()
                    f.close()
            with open(output, "w") as f:
                f.writelines("%s\n" % line for line in blacklists)
                f.close()
        line = 0
        if(os.path.exists(output)):
            with open(output, "r") as f:
                blacklists = f.read().splitlines()
            for key in blacklists:
                for file in files:
                    if(os.path.exists(path+"/"+file)):
                        os.system(
                            "ex +g/\"{0}\"/d -cwq {1}".format(key.strip(), path+"/"+file))
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # initializes & keeps only whitelisted targets
    def whitelist(self, whitelist=""):
        domain = self.domain
        path = self.path
        output = path+"/whitelist.kenz"
        files = []
        for x in os.listdir(path):
            if x.endswith(".kenz") and x not in ["blacklist.kenz", "whitelist.kenz", "program.kenz", "repoenum.kenz", "reposcan.kenz", "portscan.kenz", "vizscan.kenz"]:
                files.append(x)
        whitelists = []
        if(len(whitelist) > 0):
            whitelists.append(whitelist)
            if(os.path.exists(output)):
                with open(output, "r") as f:
                    whitelists.extend(f.read().splitlines())
                    whitelists = list(set(whitelists))
                    whitelists.sort()
                    f.close()
            with open(output, "w") as f:
                f.writelines("%s\n" % line for line in whitelists)
                f.close()
        line = 0
        if(os.path.exists(output)):
            with open(output, "r") as f:
                whitelists = f.read().splitlines()
            for key in whitelists:
                for file in files:
                    if(os.path.exists(path+"/"+file)):
                        os.system(
                            "ex +v/\"{0}\"/d -cwq {1}".format(key.strip(), path+"/"+file))
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates subdomains
    def subenum(self):
        self.subfinder()
        self.shuffledns()
        self.amass()
        self.dnsgen()
        domain = self.domain
        path = self.path
        output = path+"/subenum.kenz"
        os.system("mv {0} {0}.old".format(output))
        os.system(
            "cat {0}/amass.log {0}/subfinder.log {0}/subenum.kenz.old {0}/shuffledns.log {0}/dnsgen.log | sort -u > {1}".format(path, output))
        self.blacklist()
        self.whitelist()
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates webservers
    def webenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/portenum.kenz"
        if(os.path.exists(subs) == False):
            return("!portenum")
        output = path+"/httpx.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        self.httpx(subs, output)
        output = path+"/webenum.kenz"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system(
            "cat {0}/httpx.log {0}/webenum.kenz.old | cut -d' ' -f 1 | sort -u | sed 's/:\\(80\\|443\\)$//' > {1}".format(path, output))
        self.blacklist()
        self.whitelist()
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates additional information for webservers
    def headenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("!webenum")
        output = path+"/headenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        extras = " -status-code -title -web-server -websocket -vhost -content-type -cdn -tech-detect "
        self.httpx(subs, output, extras)
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates social media accounts
    def socenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("!webenum")
        output = path+"/rescro.log"
        os.system("rescro -l {0} -s {1} -T 40 -o {2}".format(subs,
                                                             self.templates+"rescro.yaml", output))
        out = path+"/socenum.kenz"
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/rescro.log | sort -u  > {1}".format(path, out))
        line = 0
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates additional information for urls
    def urlheadenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/urlenum.kenz"
        if(os.path.exists(subs) == False):
            return("!urlenum")
        output = path+"/urlheadenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        extras = " -status-code -title -web-server -websocket -vhost -content-type -cdn "
        self.httpx(subs, output, extras)
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates urls
    def urlenum(self, github):
        self.gau()
        self.giturl(github)
        self.gospider()
        domain = self.domain
        path = self.path
        output = path+"/urlenum.kenz"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system(
            "cat {0}/urlenum.kenz.old {0}/gau.log {0}/giturl.log {0}/gospider.log | grep \"{2}\" | sort -u> {1}".format(path, output, domain))
        self.blacklist()
        self.whitelist()
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates github repositories using RepoHunt
    def repoenum(self, github):
        domain = self.domain
        path = self.path
        output = path+"/repoenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("repohunt -o {1} -v -k {2} -t {0}".format(github, output, domain))
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates reputation of a domain using DomREP
    def repenum(self, greynoise):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        dtype = self.dtype
        output = path+"/repenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        if dtype:
            if(os.path.exists(subs) == False):
                return("!subenum")
            self.shuffsolv(subs, domain)
            subs = path+"/shuffsolv.log"
            os.system(
                "sudo domrep -l {0} -o {1} -g {2} -T 30".format(subs, output, greynoise))
        else:
            return 0
        self.blacklist()
        self.whitelist()
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates open ports using NXScan
    def portenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        asns = path+"/asnenum.kenz"
        dtype = self.dtype
        output = path+"/portenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        if dtype:
            if(os.path.exists(subs) == False):
                return("!subenum")
            if(os.path.exists(asns) == False):
                return("!asnenum")
            self.shuffsolv(subs, domain)
            subs = path+"/shuffsolv.log"
            aslv = path+"/asnsolv.log"
            rslv = path+"/resolved.log"
            os.system(
                "cat {0} | cut -d ' ' -f 1 | sort -u > {1}".format(asns, aslv))
            os.system("cat {0} {1} | sort -u > {2}".format(aslv, subs, rslv))
            os.system(
                "sudo NXScan --only-enumerate -l {0} -o {1}".format(rslv, path+"/nxscan"))
        else:
            os.system("echo {0} > {1}".format(domain, subs))
            os.system(
                "sudo NXScan --only-enumerate -l {0} -o {1}".format(subs, path+"/nxscan"))
            os.system("rm {0}".format(subs))
        os.system(
            "cat {0}/nxscan/enum.txt | sort -u > {1}".format(path, output))
        self.blacklist()
        self.whitelist()
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates services on open ports using NXScan
    def servenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/portenum.kenz"
        if(os.path.exists(subs) == False):
            return("!portenum")
        output = path+"/servenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system(
            "sudo NXScan --only-finger -l {0} -o {1}".format(subs, path+"/nxscan"))
        os.system(
            "cat {0}/nxscan/finger.txt | sort -u > {1}".format(path, output))
        self.blacklist()
        self.whitelist()
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates dns records using DNSX
    def dnsenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("!subenum")
        output = path+"/dnsenum.kenz"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system(
            "dnsx -l {0} -o {1} -a -aaaa -cname -mx -ptr -soa -txt -resp -retry 4".format(subs, output))
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates asn using domlock
    def asnenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("!subenum")
        output = path+"/asnenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("domlock -l {0} -o {1} -T 30".format(subs, output))
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # enumerates files & directories
    def conenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("!webenum")
        self.kiterunner(subs)
        output = path+"/conenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system(
            "cat {0}/kiterunner.log | grep '] http' | sort -u > {1} ".format(path, output))
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # helper modules

    # downloads fresh list of public resolvers
    def getresolvers(self):
        output = self.resources+"/resolvers.txt"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system(
            "dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o {0}".format(output))

    def generateSubdomainsWordist(self):
        os.system("cd {0} && wget -q https://raw.githubusercontent.com/internetwache/CT_subdomains/master/top-100000.txt -O top-100000.txt".format(self.resources))
        os.system("cd {0} && wget -q https://raw.githubusercontent.com/cqsd/daily-commonspeak2/master/wordlists/subdomains.txt -O subsB.txt".format(self.resources))
        output = self.resources+"/subsA.txt"
        os.system(
            "cat {0}/top-100000.txt | cut -d ',' -f 2 | sort -u > {1}".format(self.resources, output))
        output = self.resources+"/subdomains.txt"
        os.system(
            "cat {0}/subsA.txt {0}/subsB.txt | sort -u > {1}".format(self.resources, output))

    # resolves & removes wildcard subdomains using shuffledns, puredns & dnsx
    def shuffsolv(self, domains, domain):
        self.getresolvers()
        path = self.path + "/shuffsolv.log"
        if(os.path.exists(path)):
            os.system("rm {0}".format(path))
        os.system("shuffledns -strict-wildcard -r {3}/resolvers.txt -o {0} -v -list {1} -d {2}".format(
            path, domains, domain, self.resources))
        oldp = path
        path = self.path+"/puredns.log"
        os.system("puredns resolve {1} -r {2}/resolvers.txt -l 100 -t 25 -n 5 --rate-limit-trusted 50 -w {0} --wildcard-tests 50 ".format(
            path, oldp, self.resources))
        os.system("rm "+oldp)
        oldp = path
        path = self.path+"/shuffsolv.log"
        os.system(
            "cat {1} | dnsx -wd {2} -t 40 -retry 4 -silent -rl 50| sort -u > {0}".format(path, oldp, domain))
        os.system("rm "+oldp)
        return

    # enumerates subdomains using subfinder
    #"retains wildcard domains"
    def subfinder(self):
        domain = self.domain
        path = self.path
        output = path+"/subfinder.log"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system(
            "subfinder -all -t 30 -max-time 60 -o {0} -v -timeout 20 -d {1}".format(output, domain))
        return

    # enumerates subdomains using amass
    def amass(self):
        domain = self.domain
        path = self.path
        output = path+"/amass.log"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system(
            "amass enum -o {0} -d {1} -norecursive -noalts -nolocaldb".format(output, domain))
        return

    # bruteforce non-wildcard subdomains using shuffledns
    def shuffledns(self):
        self.getresolvers()
        self.generateSubdomainsWordist()
        domain = self.domain
        path = self.path
        output = path+"/shuffledns.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("shuffledns -retries 5 -strict-wildcard -wt 30 -r {2}/resolvers.txt -w {2}/subdomains.txt -o {0} -v -d {1}".format(
            output, domain, self.resources))
        self.shuffsolv(output, domain)
        os.system("rm {0} && mv {1} {0}".format(output, path+"/shuffsolv.log"))
        return

    # enumerates subdomains using dnsgen
    def dnsgen(self):
        domain = self.domain
        path = self.path
        output = path+"/dnsgen.log"
        os.system(
            "cat {0}/amass.log {0}/subfinder.log {0}/subenum.kenz.old {0}/shuffledns.log | sort -u | dnsgen - > {1}".format(path, output))
        self.shuffsolv(output, domain)
        os.system("rm {0} && mv {1} {0}".format(output, path+"/shuffsolv.log"))
        return
        
    # probes for web servers using httpx
    def httpx(self, domains, output, extras=""):
        os.system(
            "httpx {2} -no-color -l {0} -threads 80 -retries 2 -timeout 7 -verbose -o {1}".format(domains, output, extras))
        return

    # enumerates files & directories using kiterunner
    def kiterunner(self, domains):
        domain = self.domain
        path = self.path
        path += "/kiterunner.log"
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system(
            "kr brute {0} -w {2}/kenzer-templates/kiterunner.lst -t 10s -j 80 -x 5 -q -o text | tee -a {1}".format(domains, path, self.resources))
        return

    # enumerates urls using gau
    def gau(self):
        domain = self.domain
        path = self.path
        path += "/gau.log"
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system("gau -subs -o {0} {1}".format(path, domain))
        return

    # enumerates urls using gospider
    def gospider(self):
        domain = self.domain
        path = self.path
        path += "/gospider.log"
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system(
            "gospider -S {0}/webenum.kenz -w -r --sitemap -c 10 -t 5 -o {0}/gocrawler -q -u web | sort -u > {1}".format(self.path, path))
        return

    # enumerates urls using github-endpoints
    def giturl(self, github):
        domain = self.domain
        path = self.path
        path += "/giturl.log"
        api = github
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system(
            "github-endpoints -a -t {2} -d {1} > {0}".format(path, domain, api))
        return

    # removes log files & empty files
    def remlog(self):
        os.system("rm {0}/*.log*".format(self.path))
        os.system("rm {0}/*.old*".format(self.path))
        os.system(
            "rm -r {0}/nuclei {0}/jaeles {0}/passive-jaeles {0}/nxscan {0}/gocrawler {0}/reposcan".format(self.path))
        os.system("find {0} -type f -empty -delete".format(self.path))
        return

    # splits files greater than 90mb
    def splitkenz(self):
        domain = self.domain
        path = self.path
        files = []
        for x in os.listdir(path):
            if x.endswith(".kenz") and x not in ["blacklist.kenz", "whitelist.kenz", "portscan.kenz", "vizscan.kenz", "program.kenz"]:
                files.append(x)
        for file in files:
            fil = path+"/"+file
            if os.stat(fil).st_size > 90000000:
                os.system("split -b 90M {0} {0}. -d".format(fil))
                os.system("rm {0}".format(fil))
        return

    # merges files if necessary
    def mergekenz(self):
        domain = self.domain
        path = self.path
        files = []
        for x in os.listdir(path):
            if x.endswith(".kenz") == False and ".kenz." in x:
                os.system(
                    "cat {1}/{0}.kenz.* | sort -u > {1}/{0}.kenz".format(x.split(".")[0], path))
        os.system("rm {0}/*.kenz.*".format(path))
        return
