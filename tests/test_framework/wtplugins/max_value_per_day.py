#!/usr/bin/env python3
"""A plugin which enforces a maximum total value per day.

It needs as part of its config:
    - A "data_dir" entry specifying where it is going to store its 'database'.
    - A "max_value" entry specifying the maximum value per day to enforce.

It simply stores a counter which is reset to 0 after 144 blocks (assumes no reorg).
"""

import json
import os
import sys


DATASTORE_FNAME = "datastore.json"


def read_request():
    """Read a JSON request from stdin up to the '\n' delimiter."""
    buf = ""
    while len(buf) == 0 or buf[-1] != "\n":
        buf += sys.stdin.read()
    return json.loads(buf)


def update_counter(config, counter):
    data_store = os.path.join(config["data_dir"], DATASTORE_FNAME)
    data = json.loads(open(data_store, "r").read())
    data["counter"] = counter
    open(data_store, "w+").write(json.dumps(data))


def maybe_create_data_dir(config, block_height):
    if not os.path.isdir(config["data_dir"]):
        assert not os.path.exists(config["data_dir"])
        os.makedirs(config["data_dir"])
        data_store = os.path.join(config["data_dir"], DATASTORE_FNAME)
        open(data_store, "w+").write(
            json.dumps({"counter": 0, "block_height": block_height})
        )


def current_data(config):
    with open(os.path.join(config["data_dir"], DATASTORE_FNAME), "r") as f:
        return json.loads(f.read())


if __name__ == "__main__":
    req = read_request()
    config = req["config"]
    assert "data_dir" in config and "max_value" in config
    block_info = req["block_info"]
    maybe_create_data_dir(config, req["block_height"])
    assert DATASTORE_FNAME in os.listdir(config["data_dir"])
    data = current_data(config)

    counter = data["counter"]
    if req["block_height"] >= data["block_height"] + 144:
        counter = 0

    resp = {"revault": []}
    for v in block_info["new_attempts"]:
        if counter + v["value"] > config["max_value"]:
            resp["revault"].append(v["deposit_outpoint"])
            continue
        counter += v["value"]
    update_counter(config, counter)

    sys.stdout.write(json.dumps(resp))
    sys.stdout.flush()
