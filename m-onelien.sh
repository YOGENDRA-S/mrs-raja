#/bin/bash

while getopts ":d:" input;do
    case "$input" in 
            d) domain=${OPTARG}
                    ;;
            esac 
    done        
if [ -z "$domain" ]
        then
                echo "please give a domain like \"-d domain.com\""
                exit 1 
fi



host $domain | tee -a hostinfo.txt 
dig $domain any | tee -a diginfo.txt
subfinder -d $domain -o op.txt
amass enum -passive -d $domain | tee -a op.txt
amass enum -active -d $domain | tee -a amass_ips.txt
crobat -s $domain | tee -a amass_ips.txt
cat amass_ips.txt | awk '{print $1}' | tee -a op.txt

cat op.txt | sort -u | tee -a all.txt 
cat all.txt | httprobe | tee -a alive2.txt
cat alive2.txt | sort -u | tee -a alive.txt


gau $domain | tee -a archive 1>/dev/null && gf redirect archive | cut -f 3- -d ':' | qsreplace "https://evil.com" | httpx -silent -status-code -location
