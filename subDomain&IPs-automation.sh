#!/bin/bash

while getopts ":d:" input;do
        case "$input" in
                d) domain=${OPTARG}
                        ;;
                esac
        done
if [ -z "$domain" ]     
        then
                echo "Please give a domain like \"-d domain.com\""
                exit 1
fi

#!/bin/bas

while getopts ":b:" input;do
        case "$input" in
                b) burp=${OPTARG}
                        ;;
                esac
        done
if [ -k "$burp" ]     
        then
                echo "Please give a burp like \"-b burpfdsfsfsfsfsdf.net\""
                exit 1
fi



echo "Recon1 this script for Sub-domain enumeration and roots/seeds means ips finding ,whois,dnsrecon only"

rm -rf /home/robileak/Documents/amass2/amass.txt 
rm -rf /home/robileak/Documents/amass1/amass.txt 

whois $domain | tee -a whoisMain.txt
host $domain | tee -a hostInfo.txt
dig $domain any | tee -a digInfo.txt
# python3 tools/dnsrecon/dnsrecon.py -d $domain | tee -a dnsrecon.txt
subfinder -d $domain -o op.txt  
assetfinder --subs-only $domain | tee -a op.txt
cd

docker run -v /home/robileak/Documents/amass1/:/.config/amass/ amass enum -passive -d $domain

cd

cat /home/hackingforhelp/Documents/amass1/amass.txt | tee -a op.txt

# docker run -v /home/hackingforhelp/Documents/amass2/:/.config/amass/ amass enum -active -d $domain -ip
cd

cat home/hackingforhelp/Documents/amass2/amass.txt | tee -a amass_ips.txt

rm -rf /home/hackingforhelp/Documents/amass2/amass.txt 

rm -rf /home/hackingforhelp/Documents/amass1/amass.txt 






cat amass_ips.txt | awk '{print $1}' | tee -a op.txt
cat op.txt | sort -u | tee -a all.txt
echo -e "######Starting Bruteforce######\n"
mv results_output.txt dns_op.txt
cat dns_op.txt output.txt

cat output.txt | sort -u | tee -a all.txt
echo "Checking for alive subdomains"
cat all.txt | httprobe | tee -a alive2.txt
cat alive2.txt | sort -u | tee -a alive.txt

echo "Checking for Sub-domain TakeOver "
subzy -targets all.txt | tee -a subdomainTakeOver.txt


~/tools/massdns/bin/massdns -r ~/tools/massdns/lists/resolvers.txt -q -t A -o S -w massdns.raw all.txt
cat massdns.raw | grep -e ' A ' |  cut -d 'A' -f 2 | tr -d ' ' > massdns.txt
cat *.txt | sort -V | uniq > $IP_PATH/final-ips.txt
echo -e "${BLUE}[*] Check the list of IP addresses at $IP_PATH/final-ips.txt${RESET}"




