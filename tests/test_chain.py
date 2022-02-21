"""Tests related to the tracking of the chain state.

This includes the tracking the status of the vaults, wallet transactions,
handling of reorgs, etc..
"""

import logging
import pytest

from fixtures import *
from test_framework import serializations
from test_framework.utils import (
    POSTGRES_IS_SETUP,
    wait_for,
)


def timestamps_from_status(status):
    """Given a vault status, what timestamps should be present."""
    assert status != "unconfirmed"
    timestamps = ["funded_at"]

    # FIXME: how about the emergency statuses?
    if status in [
        "secured",
        "active",
        "unvaulting",
        "unvaulted",
        "spending",
        "spent",
        "canceling",
        "canceled",
    ]:
        timestamps.append("secured_at")
    if status in [
        "active",
        "unvaulting",
        "unvaulted",
        "spending",
        "spent",
        "canceling",
        "canceled",
    ]:
        timestamps.append("delegated_at")
    if status in ["spend", "canceled"]:
        timestamps.append("moved_at")

    return timestamps


def reorg(revault_network, bitcoind, stop_wallets, height, shift=0):
    if stop_wallets:
        revault_network.stop_wallets()
    bitcoind.simple_reorg(height, shift=shift)
    if stop_wallets:
        revault_network.start_wallets()


def reorg_deposit(revault_network, bitcoind, deposit, stop_wallets, target_status):
    """Reorganize the chain around a deposit according to different scenarii.
    The deposit must refer to a vault that is at least confirmed.
    The `stop_wallets` parameter controls whether to stop the daemons during a reorg.
    The `target_status` parameter indicates the expected status of the vault if its
    deposit transaction gets unconfirmed then re-confirmed.
    """
    vault = revault_network.stk(0).rpc.listvaults([], [deposit])["vaults"][0]
    initial_confs = bitcoind.rpc.getblockcount() - vault["blockheight"] + 1
    logging.info(
        f"Initial vault blockheight {vault['blockheight']} ({initial_confs} confs)"
    )

    # Sanity check the timestamps
    for field in timestamps_from_status(vault["status"]):
        assert vault[field] is not None, field

    # Mine a block and reorg it, it should not affect us since the deposit would still
    # have more than 6 confs.
    bitcoind.generate_block(1)
    height = bitcoind.rpc.getblockcount()
    for w in revault_network.participants():
        wait_for(lambda: w.rpc.getinfo()["blockheight"] == height)
    reorg(revault_network, bitcoind, stop_wallets, height)
    new_tip = f"{height + 1}.*{bitcoind.rpc.getblockhash(height + 1)}"
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Found common ancestor at height {height - 1}",
                f"Vault deposit '{deposit}' still has {initial_confs} confirmations at common ancestor",
                "Rescan .*done",
                f"New tip.* {new_tip}",
            ]
        )
        v = w.rpc.listvaults([], [deposit])["vaults"][0]
        assert v["status"] == vault["status"]
        for field in timestamps_from_status(vault["status"]):
            assert v[field] is not None, field
    for w in revault_network.participants():
        wait_for(lambda: w.rpc.getinfo()["blockheight"] == height + 1)

    height = bitcoind.rpc.getblockcount()
    vault = w.rpc.listvaults([], [deposit])["vaults"][0]
    confs = height + 1 - vault["blockheight"]
    logging.info(
        f"After first reorg. Vault blockheight {vault['blockheight']} ({confs} confs)"
    )

    # Now actually shift it out.
    # It won't transition to 'funded'...
    reorg(revault_network, bitcoind, stop_wallets, vault["blockheight"], shift=-1)
    new_tip = f"{height + 1}.*{bitcoind.rpc.getblockhash(height + 1)}"
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Found common ancestor at height {vault['blockheight'] - 1}",
                f"Vault deposit '{deposit}' has 0 confirmations at common ancestor",
                "Rescan .*done",
                f"New tip.* {new_tip}",
            ]
        )
    for w in revault_network.participants():
        wait_for(lambda: w.rpc.getinfo()["blockheight"] == height + 1)
    for w in revault_network.participants():
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"]
            == "unconfirmed"
        )
        vault = w.rpc.listvaults([], [deposit])["vaults"][0]
        for field in ["funded_at", "secured_at", "delegated_at", "moved_at"]:
            assert vault[field] is None, field

    # ... But it will if we re-confirm it!
    bitcoind.generate_block(6, wait_for_mempool=vault["txid"])
    for w in revault_network.participants():
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"]
            == target_status
        )
        vault = w.rpc.listvaults([], [deposit])["vaults"][0]
        for field in timestamps_from_status(target_status):
            assert vault[field] is not None, field

    height = bitcoind.rpc.getblockcount()
    vault = w.rpc.listvaults([], [deposit])["vaults"][0]
    confs = height + 1 - vault["blockheight"]
    logging.info(
        f"After second reorg. Vault blockheight {vault['blockheight']} ({confs} confs)"
    )

    # Now reorg 1 block of the 6 making the vault funded. This should get the deposit under
    # the minimum number of confirmations threshold.
    # But since the newly connected chain has as many blocks, the vault will get back to
    # 'funded'. And since the deposit didn't change, the signatures on the coordinator are
    # still valid. It will re-download them and transition back to 'secured' / 'active'. Then
    # if some second-stage transactions were broadcasted, they will be re-broadcast.
    reorged_block_height = vault["blockheight"] + 5
    reorg(revault_network, bitcoind, stop_wallets, reorged_block_height)
    new_tip = f"{height + 1}.*{bitcoind.rpc.getblockhash(height + 1)}"
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Found common ancestor at height {reorged_block_height - 1}",
                f"Vault deposit '{deposit}' has 5 confirmations at common ancestor",
                "Rescan .*done",
                f"New tip.* {new_tip}",
            ]
        )
    for w in revault_network.participants():
        wait_for(lambda: w.rpc.getinfo()["blockheight"] == height + 1)
    for w in revault_network.participants():
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"]
            == target_status
        )
        vault = w.rpc.listvaults([], [deposit])["vaults"][0]
        for field in timestamps_from_status(target_status):
            assert vault[field] is not None, field

    height = bitcoind.rpc.getblockcount()
    vault = w.rpc.listvaults([], [deposit])["vaults"][0]
    confs = height + 1 - vault["blockheight"]
    logging.info(
        f"After third reorg. Vault blockheight {vault['blockheight']} ({confs} confs)"
    )

    # Now reorg up to the deposit. The same will happen.
    reorg(revault_network, bitcoind, stop_wallets, vault["blockheight"])
    new_tip = f"{height + 1}.*{bitcoind.rpc.getblockhash(height + 1)}"
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Found common ancestor at height {vault['blockheight'] - 1}",
                f"Vault deposit '{deposit}' has 0 confirmations at common ancestor",
                "Rescan .*done",
                f"New tip.* {new_tip}",
            ]
        )
    for w in revault_network.participants():
        wait_for(lambda: w.rpc.getinfo()["blockheight"] == height + 1)
    for w in revault_network.participants():
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"]
            == target_status
        )
        for field in timestamps_from_status(target_status):
            assert vault[field] is not None, field

    height = bitcoind.rpc.getblockcount()
    vault = w.rpc.listvaults([], [deposit])["vaults"][0]
    confs = height + 1 - vault["blockheight"]
    logging.info(
        f"After fourth reorg. Vault blockheight {vault['blockheight']} ({confs} confs)"
    )

    # TODO: try with tx malleation


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_reorged_deposit_status_1(revault_network, bitcoind):
    # NOTE: bitcoind would discard updating the mempool if the reorg is >10 blocks long.
    revault_network.deploy(4, 2, csv=12, with_watchtowers=False)

    # Play with the chain on a vault which is 'secured'
    vault = revault_network.fund(0.14)
    deposit = f"{vault['txid']}:{vault['vout']}"
    revault_network.secure_vault(vault)
    for stop_wallets in [True, False]:
        logging.info(f"For secured vault '{deposit}'. Stop wallets: {stop_wallets}")
        reorg_deposit(
            revault_network, bitcoind, deposit, stop_wallets, target_status="secured"
        )

    # Now on a vault that is 'active'
    vault = revault_network.fund(0.28)
    deposit = f"{vault['txid']}:{vault['vout']}"
    revault_network.activate_fresh_vaults([vault])
    for stop_wallets in [True, False]:
        logging.info(f"For active vault '{deposit}'. Stop wallets: {stop_wallets}")
        reorg_deposit(
            revault_network, bitcoind, deposit, stop_wallets, target_status="active"
        )

    # Now on a vault that is 'unvaulted'
    vault = revault_network.fund(0.56)
    deposit = f"{vault['txid']}:{vault['vout']}"
    revault_network.activate_fresh_vaults([vault])
    revault_network.unvault_vaults_anyhow([vault])
    for stop_wallets in [True, False]:
        logging.info(f"For unvaulted vault '{deposit}'. Stop wallets: {stop_wallets}")
        reorg_deposit(
            revault_network, bitcoind, deposit, stop_wallets, target_status="unvaulted"
        )

    # TODO: same with 'emergency'


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_reorged_deposit_status_2(revault_network, bitcoind):
    # NOTE: bitcoind would discard updating the mempool if the reorg is >10 blocks long.
    revault_network.deploy(4, 2, csv=3, with_watchtowers=False)

    # Now on a vault that is 'spent'
    vault = revault_network.fund(1.12)
    deposit = f"{vault['txid']}:{vault['vout']}"
    revault_network.activate_fresh_vaults([vault])
    revault_network.spend_vaults_anyhow([vault])
    for stop_wallets in [True, False]:
        logging.info(f"For spent vault '{deposit}'. Stop wallets: {stop_wallets}")
        # Target "unvaulted" as Spend txs get wiped from DB
        reorg_deposit(
            revault_network, bitcoind, deposit, stop_wallets, target_status="unvaulted"
        )

    # And finally the same dance with a 'canceled' vault
    vault = revault_network.fund(2.24)
    deposit = f"{vault['txid']}:{vault['vout']}"
    revault_network.activate_fresh_vaults([vault])
    revault_network.unvault_vaults_anyhow([vault])
    revault_network.cancel_vault(vault)
    for stop_wallets in [True, False]:
        logging.info(f"For canceled vault '{deposit}'. Stop wallets: {stop_wallets}")
        reorg_deposit(
            revault_network, bitcoind, deposit, stop_wallets, target_status="canceled"
        )

    # TODO: same with 'unvault_emergency'


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_reorged_unvault(revault_network, bitcoind):
    """Test various scenarii with reorgs around the Unvault transaction of a vault."""
    CSV = 12
    revault_network.deploy(4, 2, csv=CSV, with_watchtowers=False)
    man = revault_network.man(0)
    vaults = revault_network.fundmany([32, 3])
    deposits = []
    amounts = []
    for v in vaults:
        revault_network.secure_vault(v)
        revault_network.activate_vault(v)
        deposits.append(f"{v['txid']}:{v['vout']}")
        amounts.append(v["amount"])

    addr = bitcoind.rpc.getnewaddress()
    amount = sum(amounts)
    feerate = 1
    fee = revault_network.compute_spendtx_fees(feerate, len(vaults), 1)
    destinations = {addr: amount - fee}
    revault_network.unvault_vaults(vaults, destinations, feerate)
    bitcoind.generate_block(1)

    unvault_tx_a = man.rpc.listonchaintransactions([deposits[0]])[
        "onchain_transactions"
    ][0]["unvault"]
    unvault_tx_b = man.rpc.listonchaintransactions([deposits[1]])[
        "onchain_transactions"
    ][0]["unvault"]

    # Initial sanity checks..
    assert unvault_tx_a["blockheight"] == unvault_tx_b["blockheight"]
    for w in revault_network.participants():
        wait_for(lambda: w.rpc.getinfo()["blockheight"] == bitcoind.rpc.getblockcount())
        assert len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"]) == len(deposits)
        for vault in w.rpc.listvaults(["unvaulted"], deposits)["vaults"]:
            assert vault["moved_at"] is None
            for field in timestamps_from_status("unvaulted"):
                assert vault[field] is not None, field

    # First, if we reorg but not up to the Unvault tx height, nothing will happen.
    bitcoind.simple_reorg(unvault_tx_a["blockheight"] + 1)
    height = bitcoind.rpc.getblockcount()
    new_tip = f"{height}.*{bitcoind.rpc.getblockhash(height)}"
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"{deposits[0]}.* Unvault transaction is still confirmed .*'{unvault_tx_a['blockheight']}'",
                f"{deposits[1]}.* Unvault transaction is still confirmed .*'{unvault_tx_b['blockheight']}'",
                "Rescan .*done",
                f"New tip.* {new_tip}",
            ]
        )
        assert len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"]) == len(deposits)
        for vault in w.rpc.listvaults(["unvaulted"], deposits)["vaults"]:
            assert vault["moved_at"] is None
            for field in timestamps_from_status("unvaulted"):
                assert vault[field] is not None, field

    # Now, if the Unvault tx moves we'll rewind up to the ancestor, rescan the chain
    # and get back to the 'unvaulted' state.
    bitcoind.simple_reorg(unvault_tx_a["blockheight"], shift=1)
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposits[0]}'s Unvault transaction .* got unconfirmed",
                f"Vault {deposits[1]}'s Unvault transaction .* got unconfirmed",
                "Rescan of all vaults in db done.",
            ]
        )
    for w in revault_network.participants():
        wait_for(lambda: w.rpc.getinfo()["blockheight"] == bitcoind.rpc.getblockcount())
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )
        for vault in w.rpc.listvaults(["unvaulted"], deposits)["vaults"]:
            assert vault["moved_at"] is None
            for field in timestamps_from_status("unvaulted"):
                assert vault[field] is not None, field

    # If it's not confirmed anymore, we'll detect it and mark the vault as unvaulting
    unvault_tx_a = man.rpc.listonchaintransactions([deposits[0]])[
        "onchain_transactions"
    ][0]["unvault"]
    bitcoind.simple_reorg(unvault_tx_a["blockheight"], shift=-1)
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposits[0]}'s Unvault transaction .* got unconfirmed",
                f"Vault {deposits[1]}'s Unvault transaction .* got unconfirmed",
                "Rescan of all vaults in db done.",
            ]
        )
    for w in revault_network.participants():
        wait_for(lambda: w.rpc.getinfo()["blockheight"] == bitcoind.rpc.getblockcount())
        assert len(w.rpc.listvaults(["unvaulting"], deposits)["vaults"]) == len(
            deposits
        )
        for vault in w.rpc.listvaults(["unvaulting"], deposits)["vaults"]:
            assert vault["moved_at"] is None
            for field in timestamps_from_status("unvaulting"):
                assert vault[field] is not None, field

    # Now if we are spending
    # unvault_vault() above actually registered the Spend transaction, so we can activate
    # it by generating enough block for it to be mature.
    # NOTE: this exercises the logic of "jump from unvaulting to spending state"
    assert len(bitcoind.rpc.getrawmempool()) == len(vaults)
    bitcoind.generate_block(1, wait_for_mempool=len(vaults))
    bitcoind.generate_block(CSV - 1)
    for w in revault_network.participants():
        wait_for(lambda: w.rpc.getinfo()["blockheight"] == bitcoind.rpc.getblockcount())
        wait_for(
            lambda: len(w.rpc.listvaults(["spending"], deposits)["vaults"])
            == len(deposits)
        )
        for vault in w.rpc.listvaults(["spending"], deposits)["vaults"]:
            assert vault["moved_at"] is None
            for field in timestamps_from_status("spending"):
                assert vault[field] is not None, field

    # If we are 'spending' and the Unvault gets unconfirmed, we'll rewind, get back to
    # unvaulting, and mark the Spend for re-broadcast
    unvault_tx_a = man.rpc.listonchaintransactions([deposits[0]])[
        "onchain_transactions"
    ][0]["unvault"]
    bitcoind.simple_reorg(unvault_tx_a["blockheight"], shift=-1)
    height = bitcoind.rpc.getblockcount()
    new_tip = f"{height}.*{bitcoind.rpc.getblockhash(height)}"
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposits[0]}'s Unvault transaction .* got unconfirmed",
                f"Vault {deposits[1]}'s Unvault transaction .* got unconfirmed",
                "Rescan of all vaults in db done.",
                f"New tip.* {new_tip}",
            ]
        )
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulting"], deposits)["vaults"])
            == len(deposits)
        )
        for vault in w.rpc.listvaults(["unvaulting"], deposits)["vaults"]:
            assert vault["moved_at"] is None
            for field in timestamps_from_status("unvaulting"):
                assert vault[field] is not None, field

    # Get to re-broadcast the spend
    bitcoind.generate_block(1, wait_for_mempool=len(vaults))
    bitcoind.generate_block(CSV - 1)
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["spending"], deposits)["vaults"])
            == len(deposits)
        )
        for vault in w.rpc.listvaults(["spending"], deposits)["vaults"]:
            assert vault["moved_at"] is None
            for field in timestamps_from_status("spending"):
                assert vault[field] is not None, field

    # And confirm it
    bitcoind.generate_block(1, wait_for_mempool=1)
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )
        for vault in w.rpc.listvaults(["spent"], deposits)["vaults"]:
            for field in timestamps_from_status("spent"):
                assert vault[field] is not None, field


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_reorged_spend(revault_network, bitcoind):
    CSV = 12
    revault_network.deploy(4, 2, csv=CSV, with_watchtowers=False)
    vaults = revault_network.fundmany([32, 3])

    # Spend the vaults, record the spend time
    revault_network.activate_fresh_vaults(vaults)
    deposits, _ = revault_network.spend_vaults_anyhow(vaults)
    initial_moved_at = revault_network.stk(0).rpc.listvaults(["spent"])["vaults"][0][
        "moved_at"
    ]

    # Initial sanity checks..
    for w in revault_network.participants():
        wait_for(lambda: w.rpc.getinfo()["blockheight"] == bitcoind.rpc.getblockcount())
        assert len(w.rpc.listvaults(["spent"], deposits)["vaults"]) == len(deposits)
        for vault in w.rpc.listvaults(["spent"], deposits)["vaults"]:
            for field in timestamps_from_status("spent"):
                assert vault[field] is not None, field

    # If we are 'spent' and the Spend gets unconfirmed, it'll get marked for
    # re-broadcast
    blockheight = bitcoind.rpc.getblockcount()
    bitcoind.simple_reorg(blockheight, shift=-1)
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposits[0]}'s Spend transaction .* got unconfirmed",
                f"Vault {deposits[1]}'s Spend transaction .* got unconfirmed",
                "Rescan of all vaults in db done.",
            ]
        )

    # All good if we re-confirm it
    bitcoind.generate_block(1, wait_for_mempool=1)
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )
        for vault in w.rpc.listvaults(["spent"], deposits)["vaults"]:
            for field in timestamps_from_status("spent"):
                assert vault[field] is not None, field
            # It's in a new block, it shouldn't have the same timestamp!
            assert vault["moved_at"] != initial_moved_at


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_reorged_cancel(revault_network, bitcoind):
    revault_network.deploy(4, 2, csv=12, with_watchtowers=False)
    stks = revault_network.stks()
    mans = revault_network.mans()
    vault = revault_network.fund(32)
    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposit = f"{vault['txid']}:{vault['vout']}"
    amount = vault["amount"]

    addr = bitcoind.rpc.getnewaddress()
    feerate = 1
    fee = revault_network.compute_spendtx_fees(feerate, 1, 1)
    destinations = {addr: amount - fee}
    revault_network.unvault_vaults([vault], destinations, feerate)
    unvault_tx = mans[0].rpc.listonchaintransactions([deposit])["onchain_transactions"][
        0
    ]["unvault"]

    # Now let's cancel the spending
    revault_network.cancel_vault(vault)
    cancel_tx = mans[0].rpc.listonchaintransactions([deposit])["onchain_transactions"][
        0
    ]["cancel"]
    initial_moved_at = revault_network.stk(0).rpc.listvaults()["vaults"][0]["moved_at"]

    # Reorging, but not unconfirming the cancel
    bitcoind.simple_reorg(cancel_tx["blockheight"])
    for w in stks + mans:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposit}'s Cancel transaction .* got unconfirmed",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: w.rpc.getinfo()["blockheight"] == bitcoind.rpc.getblockcount())

    # Let's unconfirm the cancel and check that the vault is now in 'canceling' state
    bitcoind.simple_reorg(cancel_tx["blockheight"], shift=-1)
    for w in stks + mans:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposit}'s Cancel transaction .* got unconfirmed",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: w.rpc.getinfo()["blockheight"] == bitcoind.rpc.getblockcount())
    for w in stks + mans:
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"]
            == "canceling"
        )
        assert w.rpc.listvaults([], [deposit])["vaults"][0]["moved_at"] is None
        for field in timestamps_from_status("canceling"):
            assert w.rpc.listvaults([], [deposit])["vaults"][0][field] is not None

    # Confirming the cancel again
    bitcoind.generate_block(1, wait_for_mempool=1)
    for w in stks + mans:
        w.wait_for_log("Cancel tx .* was confirmed at height .*")
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"] == "canceled"
        )
        for field in timestamps_from_status("canceled"):
            vault = w.rpc.listvaults([], [deposit])["vaults"][0]
            assert vault[field] is not None
            # It's in a new block, it shouldn't have the same timestamp!
            assert vault["moved_at"] != initial_moved_at

    # Let's unconfirm the unvault
    bitcoind.simple_reorg(unvault_tx["blockheight"], shift=-1)
    for w in stks + mans:
        w.wait_for_log(f"Vault {deposit}'s Unvault transaction .* got unconfirmed")

    # Here we go canceling everything again
    bitcoind.generate_block(1, wait_for_mempool=2)
    for w in stks + mans:
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"] == "canceled"
        )
        for field in timestamps_from_status("canceled"):
            assert [field] is not None


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_retrieve_vault_status(revault_network, bitcoind):
    """Test we keep track of coins that moved without us actively noticing it."""
    CSV = 3
    revault_network.deploy(2, 2, csv=CSV)
    stks = revault_network.stk_wallets
    # We don't use mans() here as we need a reference to the actual list in order to
    # modify it.
    mans = revault_network.man_wallets

    # Create a new deposit, makes everyone aware of it. Then stop one of the
    # wallets for it to not notice anything from now on.
    vault = revault_network.fund(0.05)
    man = mans.pop(0)
    man.stop()

    # Now activate and Spend the vault, the manager does not acknowledge it (yet)
    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposits = [f"{vault['txid']}:{vault['vout']}"]
    destinations = {bitcoind.rpc.getnewaddress(): vault["amount"] // 2}
    spend_tx = mans[0].rpc.getspendtx(deposits, destinations, 1)["spend_tx"]
    for m in [man] + mans:
        spend_tx = m.man_keychain.sign_spend_psbt(spend_tx, [vault["derivation_index"]])
        mans[0].rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    mans[0].rpc.setspendtx(spend_psbt.tx.hash)

    bitcoind.generate_block(1, wait_for_mempool=len(deposits))
    bitcoind.generate_block(CSV)
    mans[0].wait_for_log(
        f"Succesfully broadcasted Spend tx '{spend_psbt.tx.hash}'",
    )
    wait_for(lambda: len(mans[0].rpc.listvaults(["spending"], deposits)["vaults"]) == 1)

    # The manager should restart, and acknowledge the vault as being "spending"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(mans[0].rpc.listvaults(["spending"], deposits)["vaults"])
        == len(deposits)
    )

    # And if we mine it now everyone will see it as "spent"
    bitcoind.generate_block(1, wait_for_mempool=spend_psbt.tx.hash)
    for w in mans + revault_network.stks():
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )

    # Now do the same dance with a "spent" vault
    vault = revault_network.fund(0.14)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposits = [f"{vault['txid']}:{vault['vout']}"]
    destinations = {bitcoind.rpc.getnewaddress(): vault["amount"] // 2}
    spend_tx = mans[0].rpc.getspendtx(deposits, destinations, 1)["spend_tx"]
    for m in [man] + mans:
        spend_tx = m.man_keychain.sign_spend_psbt(spend_tx, [vault["derivation_index"]])
        mans[0].rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    mans[0].rpc.setspendtx(spend_psbt.tx.hash)

    bitcoind.generate_block(1, wait_for_mempool=len(deposits))
    bitcoind.generate_block(CSV)
    mans[0].wait_for_log(
        f"Succesfully broadcasted Spend tx '{spend_psbt.tx.hash}'",
    )
    bitcoind.generate_block(1, wait_for_mempool=spend_psbt.tx.hash)
    for w in mans + revault_network.stks():
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )

    # The manager should restart, and acknowledge the vault as being "spent"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(mans[0].rpc.listvaults(["spent"], [deposit])["vaults"])
        == len(deposits)
    )

    # Now do the same dance with a "canceling" vault
    vault = revault_network.fund(8)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposits = [f"{vault['txid']}:{vault['vout']}"]
    destinations = {bitcoind.rpc.getnewaddress(): vault["amount"] // 2}
    spend_tx = mans[0].rpc.getspendtx(deposits, destinations, 1)["spend_tx"]
    for m in [man] + mans:
        spend_tx = m.man_keychain.sign_spend_psbt(spend_tx, [vault["derivation_index"]])
        mans[0].rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    mans[0].rpc.setspendtx(spend_psbt.tx.hash)
    bitcoind.generate_block(1, wait_for_mempool=len(deposits))

    # Cancel it
    for w in mans + revault_network.stks():
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )
    mans[0].rpc.revault(deposits[0])
    for w in mans + revault_network.stks():
        wait_for(
            lambda: len(w.rpc.listvaults(["canceling"], deposits)["vaults"])
            == len(deposits)
        )
    # The manager should restart, and acknowledge the vault as being "canceling"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(mans[0].rpc.listvaults(["canceling"], [deposit])["vaults"])
        == len(deposits)
    )

    # Now do the same dance with a "canceled" vault
    vault = revault_network.fund(19)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposits = [f"{vault['txid']}:{vault['vout']}"]
    destinations = {bitcoind.rpc.getnewaddress(): vault["amount"] // 2}
    spend_tx = mans[0].rpc.getspendtx(deposits, destinations, 1)["spend_tx"]
    for m in [man] + mans:
        spend_tx = m.man_keychain.sign_spend_psbt(spend_tx, [vault["derivation_index"]])
        mans[0].rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    mans[0].rpc.setspendtx(spend_psbt.tx.hash)
    bitcoind.generate_block(1, wait_for_mempool=len(deposits))

    # Cancel it
    for w in mans + revault_network.stks():
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )
    mans[0].rpc.revault(deposits[0])
    bitcoind.generate_block(1, wait_for_mempool=1)
    for w in mans + revault_network.stks():
        wait_for(
            lambda: len(w.rpc.listvaults(["canceled"], deposits)["vaults"])
            == len(deposits)
        )
    # The manager should restart, and acknowledge the vault as being "canceled"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(mans[0].rpc.listvaults(["canceled"], [deposit])["vaults"])
        == len(deposits)
    )

    # Now do the same dance with a "unvaulting" vault
    vault = revault_network.fund(41)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposits = [f"{vault['txid']}:{vault['vout']}"]
    destinations = {bitcoind.rpc.getnewaddress(): vault["amount"] // 2}
    spend_tx = mans[0].rpc.getspendtx(deposits, destinations, 1)["spend_tx"]
    for m in [man] + mans:
        spend_tx = m.man_keychain.sign_spend_psbt(spend_tx, [vault["derivation_index"]])
        mans[0].rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    mans[0].rpc.setspendtx(spend_psbt.tx.hash)

    for w in mans + revault_network.stks():
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulting"], deposits)["vaults"])
            == len(deposits)
        )

    # The manager should restart, and acknowledge the vault as being "unvaulting"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(mans[0].rpc.listvaults(["unvaulting"], [deposit])["vaults"])
        == len(deposits)
    )

    # Now do the same dance with a "unvaulted" vault
    vault = revault_network.fund(99)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)
    deposits = [f"{vault['txid']}:{vault['vout']}"]
    destinations = {bitcoind.rpc.getnewaddress(): vault["amount"] // 2}
    spend_tx = mans[0].rpc.getspendtx(deposits, destinations, 1)["spend_tx"]
    for m in [man] + mans:
        spend_tx = m.man_keychain.sign_spend_psbt(spend_tx, [vault["derivation_index"]])
        mans[0].rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    mans[0].rpc.setspendtx(spend_psbt.tx.hash)

    bitcoind.generate_block(1, wait_for_mempool=len(deposits))
    for w in mans + revault_network.stks():
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )

    # The manager should restart, and acknowledge the vault as being "unvaulted"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(mans[0].rpc.listvaults(["unvaulted"], [deposit])["vaults"])
        == len(deposits)
    )

    # Now do the same dance with an "active" vault
    vault = revault_network.fund(0.0556789)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)

    # The manager should restart, and acknowledge the vault as being "active"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    mans[0].wait_for_active_vaults([deposit])

    # Now do the same dance with a "secured" vault
    vault = revault_network.fund(0.123456)
    man = mans.pop(0)
    man.stop()

    revault_network.secure_vault(vault)

    # The manager should restart, and acknowledge the vault as being "secured"
    mans.insert(0, man)
    mans[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    mans[0].wait_for_secured_vaults([deposit])

    # Now do the same dance with an "emergencyvaulting" vault
    vault = revault_network.fund(0.98634)
    deposit = f"{vault['txid']}:{vault['vout']}"
    revault_network.secure_vault(vault)
    stk = stks.pop(0)
    stk.stop()

    stks[0].rpc.emergency()
    wait_for(
        lambda: len(stks[0].rpc.listvaults(["emergencyvaulting"], [deposit])["vaults"])
        == 1
    )

    # The stakeholder should restart, and acknowledge the vault as being "emergencyvaulting"
    stks.insert(0, stk)
    stks[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(stks[0].rpc.listvaults(["emergencyvaulting"], [deposit])["vaults"])
        == 1
    )

    # Now do the same dance with an "unvaultemergencyvaulting" vault
    vault = revault_network.fund(1.64329)
    deposit = f"{vault['txid']}:{vault['vout']}"
    revault_network.activate_fresh_vaults([vault])
    revault_network.unvault_vaults_anyhow([vault])
    stk = stks.pop(0)
    stk.stop()

    stks[0].rpc.emergency()
    wait_for(
        lambda: len(
            stks[0].rpc.listvaults(["unvaultemergencyvaulting"], [deposit])["vaults"]
        )
        == 1
    )

    # The stakeholder should restart, and acknowledge the vault as being "emergencyvaulting"
    stks.insert(0, stk)
    stks[0].start()
    deposit = f"{vault['txid']}:{vault['vout']}"
    wait_for(
        lambda: len(
            stks[0].rpc.listvaults(["unvaultemergencyvaulting"], [deposit])["vaults"]
        )
        == 1
    )
