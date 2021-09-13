# imports
import os
import tldextract

# monitor


class Monitor:

    # initializations
    def __init__(self, db, domains=""):
        self.domains = domains
        self.organization = "monitor"
        self.db = db
        self.path = db+self.organization
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    # core monitor modules

    # enumerates subdomains using certex
    def certex(self):
        domains = self.domains
        path = self.path
        output = path+"/certex.mon"
        if len(domains) == 0:
            os.system(
                "certex -f {0} -o {1} &".format(self.db+"../summary/domain.txt", output))
        else:
            os.system("certex -d {0} -o {1} &".format(domains, output))
        return

    # initialize automated hunt
    def initialize(self):
        path = self.path
        inp = path+"/certex.mon"
        out = path+"/subenum.mon"
        os.system("mv {0} {1}".format(inp, out))

    # reinitialize automated hunt
    def reinitialize(self):
        os.system(
            "rm {0}/*.kenz {0}/*.log {0}/*.old -r {0}/nuclei {0}/jaeles {0}/passive-jaeles {0}/nxscan {0}/gocrawler".format(self.path))

    # enumerates & filters subdomains
    def subenum(self):
        kenzerdb = self.db
        subenum = self.path+"/subenum.mon"
        if(os.path.exists(subenum) == False):
            return
        with open(subenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/monitor.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(subdomain)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/monitor.kenz"))
                os.system("rm {0}.old".format(destination+"/monitor.kenz"))
                if(os.path.exists(destination+"/blacklist.kenz")):
                    with open(destination+"/blacklist.kenz", "r") as f:
                        blacklist = f.read().splitlines()
                    for key in blacklist:
                        os.system(
                            "ex +g/\"{0}\"/d -cwq {1}".format(key.strip(), destination+"/monitor.kenz"))
                if(os.path.exists(destination+"/whitelist.kenz")):
                    with open(destination+"/whitelist.kenz", "r") as f:
                        whitelist = f.read().splitlines()
                    for key in whitelist:
                        os.system(
                            "ex +v/\"{0}\"/d -cwq {1}".format(key.strip(), destination+"/monitor.kenz"))
            except:
                continue
        output = self.path+"/subenum.kenz"
        os.system(
            "cat {0}*/monitor.kenz | sort -u > {1}".format(kenzerdb, output))
        os.system("rm {0}*/monitor.kenz".format(kenzerdb))
        line = 0
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        return line

    # normalizes enumerations
    def normalize(self):
        self.norm_subenum()
        self.norm_portenum()
        self.norm_webenum()
        self.norm_dnsenum()
        self.norm_servenum()
        self.norm_conenum()
        self.norm_repenum()
        self.norm_asnenum()
        self.norm_headenum()
        self.norm_favscan()
        self.norm_idscan()
        self.norm_cvescan()
        self.norm_subscan()
        self.norm_cscan()
        self.norm_vulnscan()
        self.norm_buckscan()
        self.reinitialize()
        return

    # normalizes subenum
    def norm_subenum(self):
        kenzerdb = self.db
        subenum = self.path+"/subenum.kenz"
        if(os.path.exists(subenum) == False):
            return
        with open(subenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/subenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(subdomain)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/subenum.kenz"))
                os.system("rm {0}.old".format(destination+"/subenum.kenz"))
            except:
                continue
        return

    # normalizes portenum
    def norm_portenum(self):
        kenzerdb = self.db
        portenum = self.path+"/portenum.kenz"
        if(os.path.exists(portenum) == False):
            return
        with open(portenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/portenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(subdomain)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/portenum.kenz"))
                os.system("rm {0}.old".format(destination+"/portenum.kenz"))
            except:
                continue
        return

    # normalizes webenum
    def norm_webenum(self):
        kenzerdb = self.db
        webenum = self.path+"/webenum.kenz"
        if(os.path.exists(webenum) == False):
            return
        with open(webenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/webenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(subdomain)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/webenum.kenz"))
                os.system("rm {0}.old".format(destination+"/webenum.kenz"))
            except:
                continue
        return

    # normalizes headenum
    def norm_headenum(self):
        kenzerdb = self.db
        headenum = self.path+"/headenum.kenz"
        if(os.path.exists(headenum) == False):
            return
        with open(headenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[0]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/headenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/headenum.kenz"))
                os.system("rm {0}.old".format(destination+"/headenum.kenz"))
            except:
                continue
        return

    # normalizes asnenum
    def norm_asnenum(self):
        kenzerdb = self.db
        asnenum = self.path+"/asnenum.kenz"
        if(os.path.exists(asnenum) == False):
            return
        with open(asnenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[0]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/asnenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/asnenum.kenz"))
                os.system("rm {0}.old".format(destination+"/asnenum.kenz"))
            except:
                continue
        return

    # normalizes dnsenum
    def norm_dnsenum(self):
        kenzerdb = self.db
        dnsenum = self.path+"/dnsenum.kenz"
        if(os.path.exists(dnsenum) == False):
            return
        with open(dnsenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/dnsenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/dnsenum.kenz"))
                os.system("rm {0}.old".format(destination+"/dnsenum.kenz"))
            except:
                continue
        return

    # normalizes favscan
    def norm_favscan(self):
        kenzerdb = self.db
        favscan = self.path+"/favscan.kenz"
        if(os.path.exists(favscan) == False):
            return
        with open(favscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split("	")[2]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/favscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/favscan.kenz"))
                os.system("rm {0}.old".format(destination+"/favscan.kenz"))
            except:
                continue
        return

    # normalizes conenum
    def norm_conenum(self):
        kenzerdb = self.db
        conenum = self.path+"/conenum.kenz"
        if(os.path.exists(conenum) == False):
            return
        with open(conenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split("]")[1].split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/conenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/conenum.kenz"))
                os.system("rm {0}.old".format(destination+"/conenum.kenz"))
            except:
                continue
        return

    # normalizes servenum
    def norm_servenum(self):
        kenzerdb = self.db
        servenum = self.path+"/servenum.kenz"
        if(os.path.exists(servenum) == False):
            return
        with open(servenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/servenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/servenum.kenz"))
                os.system("rm {0}.old".format(destination+"/servenum.kenz"))
            except:
                continue
        return

    # normalizes repenum
    def norm_repenum(self):
        kenzerdb = self.db
        repenum = self.path+"/repenum.kenz"
        if(os.path.exists(repenum) == False):
            return
        with open(repenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/repenum.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/repenum.kenz"))
                os.system("rm {0}.old".format(destination+"/repenum.kenz"))
            except:
                continue
        return

    # normalizes idscan
    def norm_idscan(self):
        kenzerdb = self.db
        idscan = self.path+"/idscan.kenz"
        if(os.path.exists(idscan) == False):
            return
        with open(idscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/idscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/idscan.kenz"))
                os.system("rm {0}.old".format(destination+"/idscan.kenz"))
            except:
                continue
        return

    # normalizes vulnscan
    def norm_vulnscan(self):
        kenzerdb = self.db
        vulnscan = self.path+"/vulnscan.kenz"
        if(os.path.exists(vulnscan) == False):
            return
        with open(vulnscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/vulnscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/vulnscan.kenz"))
                os.system("rm {0}.old".format(destination+"/vulnscan.kenz"))
            except:
                continue
        return

    # normalizes subscan
    def norm_subscan(self):
        kenzerdb = self.db
        subscan = self.path+"/subscan.kenz"
        if(os.path.exists(subscan) == False):
            return
        with open(subscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/subscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/subscan.kenz"))
                os.system("rm {0}.old".format(destination+"/subscan.kenz"))
            except:
                continue
        return

    # normalizes cscan
    def norm_cscan(self):
        kenzerdb = self.db
        cscan = self.path+"/cscan.kenz"
        if(os.path.exists(cscan) == False):
            return
        with open(cscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/cscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/cscan.kenz"))
                os.system("rm {0}.old".format(destination+"/cscan.kenz"))
            except:
                continue
        return

    # normalizes cvescan
    def norm_cvescan(self):
        kenzerdb = self.db
        cvescan = self.path+"/cvescan.kenz"
        if(os.path.exists(cvescan) == False):
            return
        with open(cvescan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/cvescan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/cvescan.kenz"))
                os.system("rm {0}.old".format(destination+"/cvescan.kenz"))
            except:
                continue
        return

    # normalizes buckscan
    def norm_buckscan(self):
        kenzerdb = self.db
        buckscan = self.path+"/buckscan.kenz"
        if(os.path.exists(buckscan) == False):
            return
        with open(buckscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains = list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/buckscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system(
                    "mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/buckscan.kenz"))
                os.system("rm {0}.old".format(destination+"/buckscan.kenz"))
            except:
                continue
        return
