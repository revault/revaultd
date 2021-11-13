#!/usr/bin/env python3
"""A plugin which returns any attempt sent to it as needing to be revaulted"""

import json
import sys


def read_request():
    """Read a JSON request from stdin up to the '\n' delimiter."""
    buf = ""
    while len(buf) == 0 or buf[-1] != "\n":
        buf += sys.stdin.read()
    return json.loads(buf)


if __name__ == "__main__":
    req = read_request()
    block_info = req["block_info"]
    resp = {"revault": [v["deposit_outpoint"] for v in block_info["new_attempts"]]}
    sys.stdout.write(json.dumps(resp))
    sys.stdout.flush()
