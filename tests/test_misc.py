from fixtures import (
    revaultd_stakeholder, revaultd_manager, bitcoind, directory, test_base_dir,
    test_name
)
from utils import TIMEOUT
import time
import json, socket

def test_revaultd_stakeholder_starts(revaultd_stakeholder):
    revaultd_stakeholder.wait_for_log("New tip")
    revaultd_stakeholder.rpc.call("stop")
    revaultd_stakeholder.wait_for_log("Stopping revaultd.")
    revaultd_stakeholder.wait_for_log("Bitcoind received shutdown.")
    revaultd_stakeholder.proc.wait(TIMEOUT)

def test_revaultd_manager_starts(revaultd_manager):
    revaultd_manager.wait_for_log("New tip")
    revaultd_manager.rpc.call("stop")
    revaultd_manager.wait_for_log("Stopping revaultd.")
    revaultd_manager.wait_for_log("Bitcoind received shutdown.")
    revaultd_manager.proc.wait(TIMEOUT)
