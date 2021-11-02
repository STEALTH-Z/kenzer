git pull
cd resources/kenzer-bin/
git pull
sudo cp * /usr/bin/
cd ../kenzer-templates
git pull
cd ../freakerdb
git pull
sudo systemctl restart kenzer.service
