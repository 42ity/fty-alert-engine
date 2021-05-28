#!/bin/sh
#set -x #trace
set +e

#manual so lib installation + services cleanup and restart
[ ! -d "./src" ] && echo "must be run from repo. root directory" && exit

echo "+compile"
make
[ $? -ne 0 ] && exit

echo "+strip so lib"
strip ./src/.libs/libfty_alert_engine.so.0.0.0

cd /usr/lib/x86_64-linux-gnu/
if [ ! -f "./libfty_alert_engine.so.0.0.0.original" ]; then
  echo "+save so lib original"
  sudo cp ./libfty_alert_engine.so.0.0.0 ./libfty_alert_engine.so.0.0.0.original
fi
cd - > /dev/null 2>&1

echo "+install so lib"
sudo cp ./src/.libs/libfty_alert_engine.so.0.0.0 /usr/lib/x86_64-linux-gnu/

echo "+stop services"
sudo /bin/systemctl stop fty-alert-engine fty-alert-list

echo "+cleanup remaining rules and state files"
sudo rm /var/lib/fty/fty-alert-engine/*.rule
sudo rm /var/lib/fty/fty-alert-engine/state
sudo rm /var/lib/fty/fty-alert-list/state_file

echo "+restart services"
sudo /bin/systemctl start fty-alert-engine fty-alert-list

#echo "+trace service (grep)"
#sudo /bin/journalctl -fu fty-alert-engine | grep ruleXphaseIsApplicable

echo "+trace service"
sudo /bin/journalctl -fu fty-alert-engine
