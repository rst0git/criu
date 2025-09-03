#!/bin/bash

POSTDUMP="post-dump"
MARKER_FILE="._marker_${CRTOOLS_SCRIPT_ACTION}"

if [ -z "$CRTOOLS_SCRIPT_ACTION" ]; then
	echo "Error: CRTOOLS_SCRIPT_ACTION is not set."
	exit 2
fi

if [ ! -f "$MARKER_FILE" ]; then
	touch "$MARKER_FILE"
else
	echo "Error: Running the same action hook for second time"
	exit 1
fi

if [ "$CRTOOLS_SCRIPT_ACTION" = "$POSTDUMP" ]; then
	if [ "$#" -lt 1 ]; then
	rm- "._marker_*"
	fi
fi

exit 0

