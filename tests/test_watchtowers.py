import os

from fixtures import *
from test_framework.utils import (
    wait_for,
    WT_PLUGINS_DIR,
    COIN,
)


def test_wt_share_revocation_txs(revault_network, bitcoind):
    """Sanity check that we share the revocation signatures with the watchtower."""
    rn = revault_network
    rn.deploy(2, 1)
    stk = rn.stk(0)

    amount = 3.4444
    v = rn.fund(amount)
    deposit = f"{v['txid']}:{v['vout']}"
    rn.secure_vault(v)
    for stk in rn.stks():
        stk.watchtower.wait_for_log(
            f"Registered a new vault at '{deposit}'",
        )


def test_wt_policy(directory, revault_network, bitcoind):
    """Test we "can't" breach the policies defined by the watchtowers"""
    rn = revault_network
    CSV = 3
    rn.deploy(2, 1, csv=CSV)
    vaults = sorted(rn.fundmany([1, 2, 2, 4, 2, 2]), key=lambda v: v["amount"])
    rn.activate_fresh_vaults(vaults)

    # By default the watchtowers are configured with a plugin enforcing no
    # spending policy.
    rn.spend_vaults_anyhow([vaults[0]])

    # If we have a single watchtower preventing any unvault, we won't be able
    # to spend.
    revault_all_path = os.path.join(WT_PLUGINS_DIR, "revault_all.py")
    rn.stks()[0].watchtower.add_plugins([{"path": revault_all_path, "config": {}}])
    rn.broadcast_unvaults_anyhow(vaults[1:3])
    bitcoind.generate_block(1, 2)
    rn.stks()[0].watchtower.wait_for_log("Broadcasted Cancel transaction")
    for stk in rn.stks():
        deposits = [f"{v['txid']}:{v['vout']}" for v in vaults[1:3]]
        wait_for(
            lambda: len(stk.rpc.listvaults(["canceling"], deposits)["vaults"]) == 2
        )
    bitcoind.generate_block(1)
    rn.stks()[0].watchtower.remove_plugins([revault_all_path])

    # Test a policy limiting the amount we can unvault per day
    max_per_day_path = os.path.join(WT_PLUGINS_DIR, "max_value_per_day.py")
    datadir = os.path.join(directory, "max_per_day_plugin_datadir")
    plugin = {
        "path": max_per_day_path,
        "config": {"max_value": 5 * COIN, "data_dir": datadir},
    }
    rn.stks()[1].watchtower.add_plugins([plugin])
    # The first one will go through (4 < 5)
    v = vaults[-1]
    assert v["amount"] == 4 * COIN
    deposits, spend_psbt = rn.spend_vaults_anyhow_unconfirmed([v])
    for stk in rn.stks():
        stk.watchtower.wait_for_log(
            f"Got a confirmed Unvault UTXO for vault at '{v['txid']}:{v['vout']}'"
        )
    bitcoind.generate_block(1, wait_for_mempool=[spend_psbt.tx.hash])
    wait_for(
        lambda: len(rn.man(0).rpc.listvaults(["spent"], deposits)["vaults"])
        == len(deposits)
    )
    # The second one won't (4 + 2 > 5)
    v = vaults[-2]
    assert v["amount"] == 2 * COIN
    assert len(bitcoind.rpc.getrawmempool()) == 0
    rn.broadcast_unvaults_anyhow([v])
    bitcoind.generate_block(1, 1)
    rn.stks()[1].watchtower.wait_for_log("Broadcasted Cancel transaction")
    for stk in rn.stks():
        deposit = f"{v['txid']}:{v['vout']}"
        wait_for(
            lambda: len(stk.rpc.listvaults(["canceling"], [deposit])["vaults"]) == 1
        )
    bitcoind.generate_block(1)
    # But it will if we wait till the next day, it'll go through
    bitcoind.generate_block(144)
    v = vaults[-3]
    assert v["amount"] == 2 * COIN
    rn.spend_vaults_anyhow([v])
