



#!/bin/bash

while getopts ":d:" input;do
        case "$input" in
                d) domain=${OPTARG}
                        ;;
                esac
        done
if [ -z "$domain" ]     
        then
                echo "Please Enter your main domain like \"-d https://domain.com\""
                exit 1
fi



cd


rm -rf /root/tools/SQLiDetector/uroWaybaclforSqliDector1.txt
rm -rf SqlidetectorMainDomainOutput.txt
rm -rf /root/tools/ParamSpider/output/*.txt
rm -rf waybackdataforSqlDetector.txt
rm -rf waybackdataforSqlDetector2.txt
rm -rf /root/tools/SQLiDetector/uroWaybaclforSqliDector2.txt
rm -rf SqlidetectorAllDomainOutput.txt
rm -rf para.txt
rm -rf SqlidetectorMainDomainOutputPara.txt
rm -rf para1.txt
rm -rf /root/tools/SQLiDetector/para1.txt













cat way2.txt | uro | tee uroWaybaclforSqliDector1.txt
mv uroWaybaclforSqliDector1.txt /root/tools/SQLiDetector/
cd /root/tools/SQLiDetector
python3 sqlidetector.py -f uroWaybaclforSqliDector1.txt -w 50 -t 20 -o SqlidetectorMainDomainOutput.txt
mv SqlidetectorMainDomainOutput.txt ../../

cd

./tools/ParamSpider/paramspider.py -d $domain | tee -a para.txt

cat para.txt | grep "http" | tee -a para1.txt
mv para1.txt /root/tools/SQLiDetector/


cd /root/tools/SQLiDetector
python3 sqlidetector.py -f para1.txt -o SqlidetectorMainDomainOutputPara.txt
mv SqlidetectorMainDomainOutputPara.txt ../../
cd
cd

cat alive.txt | waybackurls | sort -u >> waybackdataforSqlDetector.txt
cat waybackdataforSqlDetector.txt  | sort -u | grep "=" | tee -a waybackdataforSqlDetector2.txt

cat waybackdataforSqlDetector2.txt | uro | tee -a uroWaybaclforSqliDector2.txt

mv uroWaybaclforSqliDector2.txt /root/tools/SQLiDetector/

cd /root/tools/SQLiDetector

echo "now i want to show you uro sort link now look"

python3 sqlidetector.py -f uroWaybaclforSqliDector2.txt -o SqlidetectorAllDomainOutput.txt



mv SqlidetectorAllDomainOutput.txt ../../

cd



