#!/usr/bin/env bash

# exit from script if error was raised.
set -e

PARAMS=$(echo $PARAMS "--conf config.toml")


# Add user parameters to command.
PARAMS="$PARAMS $@"

echo "Command: revault_coordinatord $PARAMS"
exec revault_coordinatord $PARAMS
