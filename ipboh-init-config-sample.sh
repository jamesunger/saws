#!/bin/bash

INFOEXISTS="$(ipboh ls | grep 2c6300a9-4571-480a-832b-3bd4ba6abb58)"
while [[ "$INFOEXISTS" == "" ]]; do
        echo "Waiting for info file to exist..."
        INFOEXISTS="$(ipboh ls | grep 2c6300a9-4571-480a-832b-3bd4ba6abb58)"
        sleep 5
done
echo $INFOEXISTS
