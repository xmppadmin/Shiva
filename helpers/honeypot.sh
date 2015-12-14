#!/bin/bash

# init script for honeypot startup and shutdown
#
# if listen_interface and web_interface are given, ip on interfaces is detected and stored into 'shiva.conf'
#
listen_interface=""
web_interface=""


if [ "$UID" == "0" ] || [ "$EUID" == "0" ]
then
    printf "\n[!] Do not run shiva as root.\n\n"
    exit 1
fi

base_dir=INSTALL_PATH/shiva
reciever_dir=$base_dir/shivaReceiver/receiver
analyzer_dir=$base_dir/shivaAnalyzer/analyzer

listen_address=""
web_address=""


tmp_address=$(ip address show $listen_interface | grep inet\  | awk '{print $2}' | sed 's/\/.*//g')
if [[ $tmp_address =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  listen_address=$tmp_address
fi

tmp_address=$(ip address show $web_interface | grep inet\  | awk '{print $2}' | sed 's/\/.*//g')
if [[ $tmp_address =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  web_address=$tmp_address
fi


#replace 'listenhost' directive
if [ ! -z $listen_address ]; then
  sed -r -i "s/listenhost[[:space:]+]:[[:space:]+][0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/listenhost\ :\ $listen_address/g" $base_dir/shiva.conf
  echo "Assigning IP address for honeypot: " $listen_address
fi

#replace 'web address' directive
if [ ! -z $web_address ]; then
  sed -r -i "s/address[[:space:]+]:[[:space:]+][0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/address\ :\ $web_address/g" $base_dir/shiva.conf
  echo "Assigning IP address for web interface: "$web_address
fi

stop() {
  cd $reciever_dir
  source ../bin/activate
  if [ -f run/smtp.pid ] && kill -0 `cat run/smtp.pid`; then 
    lamson stop 2> /dev/null
  fi
  
  cd $analyzer_dir
  source ../bin/activate
  if [ -f run/smtp.pid ] && kill -0 `cat run/smtp.pid`; then 
    lamson stop 2> /dev/null
  fi
}

start() {
  cd $reciever_dir
  source ../bin/activate
  if [ -f run/smtp.pid ] && kill -0 `cat run/smtp.pid`; then
    echo "Reciverer is already running"
  else 
    echo "Starting reciever..." 
    lamson start -FORCE
  fi

  cd $analyzer_dir
  source ../bin/activate
  if [ -f run/smtp.pid ] && kill -0 `cat run/smtp.pid`; then
    echo "Analyzer is already running"
  else
    echo "Starting analyzer..." 
    lamson start -FORCE
  fi
}

case "$1" in
    start)
      start    
    ;;

    stop)
      stop
    ;;

    restart)
      stop
      start
    ;;

esac

exit 0
