#!/bin/bash
clear
apt-get install sudo
# update OS
sudo apt-get update && sudo apt-get -y upgrade && sudo apt-get -y dist-upgrade && sudo apt-get -y autoremove
# install git
apt-get install git
# Install curl
apt-get install curl
# install python setup tools
apt-get install python-setuptools
# install and upgrade pyhon-pip
apt-get install python-pip
pip install --upgrade pip
# install shiva required depedencies
apt-get install python g++ python-dev python-virtualenv exim4-daemon-light libmysqlclient-dev make libffi-dev libfuzzy-dev automake autoconf libpng12-dev libfreetype6-dev libxft-dev libblas-dev liblapack-dev gfortran spamassassin mysql-server mysql-client
