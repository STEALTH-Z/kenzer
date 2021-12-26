# KENZER | Automated web assets enumeration & scanning

## Mentions

[A Conceptual Introduction to Automating Bug Bounties](https://g147.medium.com/a-conceptual-introduction-to-automating-bug-bounties-ft-arpsyndicate-yeswehack-scanfactory-f2468f345d7)<br>

## Demo

[![kenzer](screenshots/yt-thumbnail.png)](https://www.youtube.com/watch?v=pD0IRloikz8)

## Screenshots

![kenzer](screenshots/kenzer0.png)
![kenzer](screenshots/kenzer1.png)

## Instructions for running

0. Run `git clone https://github.com/ARPSyndicate/kenzer /root/kenzer && cd /root/kenzer` **(preferred)**<br>
1. Create an account on [Zulip](https://zulipchat.com)<br>
2. Navigate to `Settings > Your Bots > Add a new bot`<br>
3. Create a new generic bot named `kenzer`<br>
4. Add all the configurations in `configs/kenzer.conf`<br>
5. Install/Run using - <br>
   - `./install.sh -b` [if you need `kenzer-compatible` binaries to be installed] **(preferred)**<br>
   - `./install.sh` [if you do not need `kenzer-compatible` binaries to be installed]<br>
   - `./run.sh` [if you do not need installation at all]<br>
   - `./service.sh` [initialize it as a service post-installation] **(preferred)**<br>
   - `bash swap.sh` [in case you are facing memory issues]
6. Interact with `kenzer` using Zulip client, by adding bot to a stream or via DM.<br>
7. Test `@**kenzer** man` as Zulip input to display available commands.<br>
8. All the commands can be used by mentioning the chatbot using the prefix `@**kenzer**`.<br>

## Built-in Modules

> - `blacklist <target>,<regex>` - initializes & removes blacklisted targets
> - `whitelist <target>,<regex>` - initializes & keeps only whitelisted targets
> - `program <target>,<link>` - initializes the program to which target belongs
> - `subenum <target>` - enumerates subdomains
> - `repenum <target>` - enumerates reputation of subdomains
> - `repoenum <target>` - enumerates github repositories
> - `portenum <target>` - enumerates open ports
> - `servenum <target>` - enumerates services
> - `webenum <target>` - enumerates webservers
> - `headenum <target>` - enumerates additional info from webservers
> - `urlheadenum <target>` - enumerates additional info from urls
> - `asnenum <target>` - enumerates asn records
> - `dnsenum <target>` - enumerates dns records
> - `conenum <target>` - enumerates hidden files & directories
> - `urlenum <target>` - enumerates urls
> - `socenum <target>` - enumerates social media accounts
> - `subscan <target>` - hunts for subdomain takeovers
> - `reposcan <target>` - scans github repositories for api key leaks
> - `cscan[-<severity>] <target>` - scan with customized templates
> - `cvescan[-<severity>] <target>` - hunts for CVEs
> - `vulnscan[-<severity>] <target>` - hunts for other common vulnerabilites
> - `urlcvescan[-<severity>] <target>` - hunts for CVEs in URLs
> - `urlvulnscan[-<severity>] <target>` - hunts for other common vulnerabilites in URLs
> - `endscan[-<severity>] <target>` - hunts for vulnerablities in custom endpoints
> - `idscan[-<severity>] <target>` - identifies applications running on webservers
> - `portscan <target>` - scans open ports
> - `buckscan <target>` - hunts for unreferenced aws s3 buckets
> - `favscan <target>` - fingerprints webservers using favicon
> - `vizscan <target>` - screenshots applications running on webservers
> - `enum <target>` - runs all enumerator modules
> - `scan <target>` - runs all scanner modules
> - `recon <target>` - runs all modules
> - `hunt <target>` - runs your custom workflow
> - `upload` - switches upload functionality
> - `upgrade` - upgrades kenzer to latest version
> - `monitor <target>` - monitors ct logs for new subdomains
> - `monitor normalize` - normalizes the enumerations from ct logs
> - `monitor db` - monitors ct logs for domains in summary/domain.txt
> - `monitor autohunt <frequency(default=5)>` - starts automated hunt while monitoring
> - `sync` - synchronizes the local kenzerdb with github
> - `kenzer <module>` - runs a specific modules
> - `kenzer man` - shows this manual

## The Beginner's Workflow

![workflow](screenshots/workflow.png)

Although few more modules are available & much more is going to be released in the course of time which can advance this workflow, yet this one is enough to get started with & listed below are few of its successful hunts.<br><br>
<img src="screenshots/adobe.png" width="200" height="60">
<img src="screenshots/ibm.png" width="150" height="60">
<img src="screenshots/amazon.png" width="150" height="50">
<img src="screenshots/algolia.png" width="250" height="60">

**COMPATIBILITY TESTED ON DEBIAN(x64) ONLY**<br>
**RIGGED WITH LOGIC ISSUES**<br>
**FEEL FREE TO SUBMIT PULL REQUESTS**
