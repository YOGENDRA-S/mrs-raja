
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



echo "Big ip scanning with nmap"
nmap -p443 --script=tools/nmapScript/http-vuln-cve2020-5902.nse -Pn -iL massdns.txt | tee -a NmapCve2020-5902.txt 

nmap -sS -sV -Pn -iL $domain -vv -n -oA testmap
brutespray --file testmap.gnmap -t 5 -T 2

echo "nmap Scan with output and Bruteforce with brutespray time taking proccess"
nmap -sS -sV -Pn -iL massdns.txt -vv -n -oA testmap
 
echo "brutespray for burteforce with nmapscan file "
brutespray --file testmap.gnmap -t 5 -T 2



# echo "ffuf Starting"
# for i in $(cat alive.txt);do ffuf -u $i/FUZZ -w /root/tools/wordlist/dicc.txt -recursion -mc 200 -t 60 ;done| tee -a ffuf_op.txt


# echo "ffuf Staring in MainDomain"


# ffuf -mc all -c -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -u "https://$domain/FUZZ" -w /root/tools/wordlist/dicc.txt -D -e js,php,bak,txt,html,zip,sql,old,gz,log,swp,yaml,yml,config,save,rsa,ppk -ac | tee -a ffufmainDomain.txt


