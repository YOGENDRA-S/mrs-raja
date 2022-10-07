#!/bin/bash


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



cd 

rm -rf way.txt
rm -rf way2.txt 
rm -rf /root/tools/SQLiDetector/uroWaybaclforSqliDector1.txt
rm -rf SqlidetectorMainDomainOutput.txt
rm -rf /root/tools/ParamSpider/Output/*.txt
rm -rf waybackdataforSqliDetector.txt
rm -rf waybackdataforSqliDetector2.txt
rm -rf /root/tools/SQLiDetector/uroWaybaclforSqliDector2.txt
rm -rf SqlidetectorAllDomainOutput.txt
rm -rf para.txt
rm -rf SqlidetectorMainDomainOutputPara.txt
rm -rf paral.txt
rm -rf /root/tools/SQLiDetector/paral.txt


echo "$domain" | waybackurls | sort -u >> way.txt
cat way.txt | sort -u | grep "=" | tee -a way2.txt
rm -rf way.txt
cat way2.txt | uro | tee -a uroWaybaclforSqliDector1.txt
mv uroWaybaclforSqliDector1.txt /root/tools/SQLiDetector/
cd /root/tools/SQLiDetector
python3 sqlidetector.py -f uroWaybaclforSqliDector1.txt -o SqlidetectorMainDomainOutput.txt
mv SqlidetectorMainDomainOutput.txt ../../

cd

./tools/ParamSpider/paramspider.py -d $domain | tee -a para.txt

cat para.txt | grep "http" | tee -a paral.txt
mv paral.txt /root/tools/SQLiDetector/


cd /root/tools/SQLiDetector
python3 paramspider.py -f paral.txt -o SqlidetectorMainDomainOutputPara.txt
mv SqlidetectorMainDomainOutputPara.txt ../../
cd 
cd 

cat alive.txt | waybackurls | sort -u >> waybackdataforSqliDetector.txt
cat waybackdataforSqliDetector.txt | sort -u | grep "=" | tee -a waybackdataforSqliDetector2.txt

cat waybackdataforSqliDetector2.txt | uro | tee -a uroWaybaclforSqliDector2.txt

mv uroWaybaclforSqliDector2.txt /root/tools/SQLiDetector/

cd /root/tools/SQLiDetector

echo "now i want to show you uro sort link now look"

python3 sqlidetector.py -f uroWaybaclforSqliDector2.txt -o SqlidetectorMainDomainOutput.txt

mv SqlidetectorMainDomainOutput.txt ../../

cd









