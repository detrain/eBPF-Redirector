#!/bin/bash

FIFO=/tmp/fifo

# Remove previous fifo
rm $FIFO
# Instantiate new fifo
mkfifo $FIFO

echo "Listening on 8080, will forward to 10.0.2.5 80"

# Create redirector
/usr/bin/nc -k -l 8080 < $FIFO | /usr/bin/nc 10.0.2.5 80 > $FIFO &

# Print pid of nc for ease of killing...
pstree -p $$