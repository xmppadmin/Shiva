#!/bin/sh

#Send SIGUSR2 signal to running SMTP server
#TODO add this file to install procedure

PID_FILE="../analyzer/run/smtp.pid";
if [ ! -r $PID_FILE ]; then
	echo "Can't read "$PID_FILE", exiting."
	exit 1
fi

PID=`cat $PID_FILE`
if [ -z "$PID" ]; then
	echo "Reading PID failed, exiting."
	exit 2
fi

kill -s 12 $PID
