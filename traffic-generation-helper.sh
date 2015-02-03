#!/bin/bash

HPING3_EXECUTABLE=/usr/sbin/hping3
HPING3_OPTS="-2 -s 2048 -p 2049 --keep -q -d 16"

if [ $1 ]
then
    DESTINATION=$1
else
    DESTINATION="127.0.0.1"
fi
echo "Using destination: $DESTINATION"

CHAR='.'
PACKET_INTERVAL=2000
PACKET_INTERVAL_STEP_SIZE=5

echo "Press any key to start packet generation."
read -n 1
echo "Starting packet generation..."
killall -9 hping3 &> /dev/null ; ($HPING3_EXECUTABLE $HPING3_OPTS -i u$PACKET_INTERVAL $DESTINATION &> /dev/null &)

echo "Valid commands are: q - quit, + - increase packet rate, - - decrease packet rate."
while [ $CHAR != 'q' ]
do
    read -n 1 -s CHAR

    case $CHAR in
    ("+")
        echo "Increasing packet rate."
        if [ $(($PACKET_INTERVAL - $PACKET_INTERVAL_STEP_SIZE)) -gt 0 ]
        then
            PACKET_INTERVAL=$(($PACKET_INTERVAL - $PACKET_INTERVAL_STEP_SIZE))
            echo "New packet interval: $PACKET_INTERVAL; Resulting theoretic packet rate: $((1000000 / $PACKET_INTERVAL)) packets/second"
            killall -9 hping3 &> /dev/null ; ($HPING3_EXECUTABLE $HPING3_OPTS -i u$PACKET_INTERVAL $DESTINATION &> /dev/null &)
        fi
        ;;
    ("-")
        echo "Decreasing packet rate."
        PACKET_INTERVAL=$(($PACKET_INTERVAL + $PACKET_INTERVAL_STEP_SIZE))
        echo "New packet interval: $PACKET_INTERVAL; Resulting theoretic packet rate: $((1000000 / $PACKET_INTERVAL)) packets/second"
        killall -9 hping3 &> /dev/null  ; ($HPING3_EXECUTABLE $HPING3_OPTS -i u$PACKET_INTERVAL $DESTINATION &> /dev/null &)
        ;;
    ("q")
        echo "Shutting down."
        ;;
    (*)
        echo "Valid commands are: q - quit, + - increase packet rate, - - decrease packet rate."
        ;;
    esac
    
    if [ $PACKET_INTERVAL -gt 60 ]
    then
        PACKET_INTERVAL_STEP_SIZE=5
    elif [ $PACKET_INTERVAL -le 60 ]
    then
        PACKET_INTERVAL_STEP_SIZE=2
    fi
done

killall -9 hping3 &> /dev/null


