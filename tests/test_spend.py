"""Tests related to the spending process.

This includes the Spend creation, announcement, broadcast, tracking, managers interaction,
etc..
"""

import pytest
import random

from bitcoin.core import COIN
from fixtures import *
from test_framework import serializations
from test_framework.utils import (
    POSTGRES_IS_SETUP,
    RpcError,
    wait_for,
)


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_spendtx_management(revault_network, bitcoind):
    CSV = 12
    revault_network.deploy(2, 1, n_stkmanagers=1, csv=CSV)
    man = revault_network.man(0)
    amount = 0.24
    vault = revault_network.fund(amount)
    deposit = f"{vault['txid']}:{vault['vout']}"

    addr = bitcoind.rpc.getnewaddress()
    spent_vaults = [deposit]
    feerate = 2
    fees = revault_network.compute_spendtx_fees(feerate, len(spent_vaults), 1)
    destination = {addr: vault["amount"] - fees}

    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)

    spend_tx = man.rpc.getspendtx(spent_vaults, destination, feerate)["spend_tx"]

    # If we are not a manager, it'll fail
    with pytest.raises(RpcError, match="This is a manager command"):
        revault_network.stk_wallets[0].rpc.updatespendtx(spend_tx)

    # But it won't if we are a stakeholder-manager
    revault_network.stkman_wallets[0].rpc.updatespendtx(spend_tx)

    # It will not accept a spend_tx which spends an unknown Unvault
    psbt = serializations.PSBT()
    psbt.deserialize(spend_tx)
    psbt.tx.vin[0].prevout.hash = 0
    insane_spend_tx = psbt.serialize()
    with pytest.raises(RpcError, match="Spend transaction refers an unknown Unvault"):
        man.rpc.updatespendtx(insane_spend_tx)

    # First time, it'll be stored
    man.rpc.updatespendtx(spend_tx)
    man.wait_for_log("Storing new Spend transaction")
    # We can actually update it no matter if it's the same
    man.rpc.updatespendtx(spend_tx)
    man.wait_for_log("Updating Spend transaction")

    assert len(man.rpc.listspendtxs()["spend_txs"]) == 1

    # If we delete it..
    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    man.rpc.delspendtx(spend_psbt.tx.hash)
    assert len(man.rpc.listspendtxs()["spend_txs"]) == 0
    # When we update it it'll be treated as a new transaction
    man.rpc.updatespendtx(spend_tx)
    man.wait_for_log("Storing new Spend transaction")
    assert len(man.rpc.listspendtxs()["spend_txs"]) == 1

    # Create another Spend transaction spending two vaults
    vault_b = revault_network.fund(amount)
    deposit_b = f"{vault_b['txid']}:{vault_b['vout']}"
    addr_b = bitcoind.rpc.getnewaddress()
    spent_vaults = [deposit, deposit_b]
    feerate = 50
    fees = revault_network.compute_spendtx_fees(feerate, len(spent_vaults), 2)
    destination = {
        addr: (vault_b["amount"] - fees) // 2,
        addr_b: (vault_b["amount"] - fees) // 2,
    }
    revault_network.secure_vault(vault_b)
    revault_network.activate_vault(vault_b)
    spend_tx_b = man.rpc.getspendtx(spent_vaults, destination, feerate)["spend_tx"]
    man.rpc.updatespendtx(spend_tx_b)
    man.wait_for_log("Storing new Spend transaction")
    assert len(man.rpc.listspendtxs()["spend_txs"]) == 2
    assert {
        "deposit_outpoints": [deposit],
        "psbt": spend_tx,
        "change_index": None,
        "cpfp_index": 0,
    } in man.rpc.listspendtxs()["spend_txs"]
    assert {
        "deposit_outpoints": [deposit, deposit_b],
        "psbt": spend_tx_b,
        "change_index": 3,
        "cpfp_index": 0,
    } in man.rpc.listspendtxs()["spend_txs"]

    # Now we could try to broadcast it..
    # But we couldn't broadcast a random txid
    with pytest.raises(RpcError, match="Unknown Spend transaction"):
        man.rpc.setspendtx(
            "d5eb741a31ebf4d2f5d6ae223900f1bd996e209150d3604fca7d9fa5d6136337"
        )

    # ..And even with an existing one we would have to sign it beforehand!
    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx_b)
    spend_psbt.tx.calc_sha256()
    with pytest.raises(
        RpcError,
        match=f"Not enough signatures, needed: {len(revault_network.mans())}, current: 0",
    ):
        man.rpc.setspendtx(spend_psbt.tx.hash)

    # Now, sign the Spend we are going to broadcast
    deriv_indexes = [vault["derivation_index"], vault_b["derivation_index"]]
    for man in revault_network.mans():
        spend_tx_b = man.man_keychain.sign_spend_psbt(spend_tx_b, deriv_indexes)

    # Just before broadcasting it, prepare a competing one to later try to make Cosigning Servers
    # sign twice
    vault_c = revault_network.fund(amount / 2)
    deposit_c = f"{vault_c['txid']}:{vault_c['vout']}"
    rogue_spent_vaults = [deposit, deposit_b, deposit_c]
    feerate = 50
    fees = revault_network.compute_spendtx_fees(feerate, len(rogue_spent_vaults), 2)
    destination = {
        addr: (vault_b["amount"] - fees) // 2,
        addr_b: (vault_b["amount"] - fees) // 2,
    }
    revault_network.secure_vault(vault_c)
    revault_network.activate_vault(vault_c)
    rogue_spend_tx = man.rpc.getspendtx(rogue_spent_vaults, destination, feerate)[
        "spend_tx"
    ]
    deriv_indexes = deriv_indexes + [vault_c["derivation_index"]]
    for man in revault_network.mans():
        rogue_spend_tx = man.man_keychain.sign_spend_psbt(rogue_spend_tx, deriv_indexes)
    man.rpc.updatespendtx(rogue_spend_tx)

    # Then broadcast the actual Spend
    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx_b)
    spend_psbt.tx.calc_sha256()
    spend_tx_b = spend_psbt.serialize()
    man.rpc.updatespendtx(spend_tx_b)
    man.rpc.setspendtx(spend_psbt.tx.hash)

    # If we show good faith (ask again for the same set of outpoints), Cosigning Servers will
    # try to be helpful.
    man.rpc.setspendtx(spend_psbt.tx.hash)

    # However, they won't let us trying to sneak in another outpoint
    rogue_spend_psbt = serializations.PSBT()
    rogue_spend_psbt.deserialize(rogue_spend_tx)
    rogue_spend_psbt.tx.calc_sha256()
    with pytest.raises(
        RpcError,
        match="one Cosigning Server already signed a Spend transaction spending one of these vaults",
    ):
        man.rpc.setspendtx(rogue_spend_psbt.tx.hash)

    # It gets marked as in the process of being unvaulted immediately (next bitcoind
    # poll), and will get marked as succesfully unvaulted after a single confirmation.
    wait_for(
        lambda: len(man.rpc.listvaults(["unvaulting"], spent_vaults)["vaults"])
        == len(spent_vaults)
    )
    bitcoind.generate_block(1, wait_for_mempool=len(spent_vaults))
    wait_for(
        lambda: len(man.rpc.listvaults(["unvaulted"], spent_vaults)["vaults"])
        == len(spent_vaults)
    )

    # We'll broadcast the Spend transaction as soon as it's valid
    bitcoind.generate_block(CSV - 1)
    man.wait_for_log(f"Succesfully broadcasted Spend tx '{spend_psbt.tx.hash}'")
    wait_for(
        lambda: len(man.rpc.listvaults(["spending"], spent_vaults)["vaults"])
        == len(spent_vaults)
    )

    # And the vault we tried to sneak in wasn't even unvaulted
    assert len(man.rpc.listvaults(["active"], [deposit_c])["vaults"]) == 1


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_spends_concurrent(revault_network, bitcoind):
    """
    Here we test the creation and succesful broadcast of both Spend transaction
    concurrently handled but non conflicting.
    """
    CSV = 1024
    revault_network.deploy(3, 2, csv=CSV)
    man = revault_network.man(1)
    # FIXME: there is something up with higher number and the test framework fee
    # computation
    amounts = [0.22, 16, 3, 21]
    vaults = revault_network.fundmany(amounts)
    # Edge case: bitcoind can actually mess up with the amounts
    amounts = []
    deposits = []
    deriv_indexes = []
    for v in vaults:
        revault_network.secure_vault(v)
        revault_network.activate_vault(v)
        deposits.append(f"{v['txid']}:{v['vout']}")
        deriv_indexes.append(v["derivation_index"])
        amounts.append(v["amount"])

    (deposits_a, deposits_b) = (deposits[:2], deposits[2:])
    (amounts_a, amounts_b) = (amounts[:2], amounts[2:])
    (indexes_a, indexes_b) = (deriv_indexes[:2], deriv_indexes[2:])

    # Spending to a P2WSH (effectively a change but hey), with a change output
    destinations = {man.rpc.getdepositaddress()["address"]: sum(amounts_a) // 2}
    spend_tx_a = man.rpc.getspendtx(deposits_a, destinations, 1)["spend_tx"]
    for man in revault_network.mans():
        spend_tx_a = man.man_keychain.sign_spend_psbt(spend_tx_a, indexes_a)
    man.rpc.updatespendtx(spend_tx_a)

    # Spending to a P2WPKH, with a change output
    destinations = {bitcoind.rpc.getnewaddress(): sum(amounts_b) // 2}
    spend_tx_b = man.rpc.getspendtx(deposits_b, destinations, 1)["spend_tx"]
    for man in revault_network.mans():
        spend_tx_b = man.man_keychain.sign_spend_psbt(spend_tx_b, indexes_b)
    man.rpc.updatespendtx(spend_tx_b)

    # Of course, we can just stop and still broadcast the Spend
    man.stop()
    man.proc.wait(10)
    man.start()

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx_a)
    spend_psbt.tx.calc_sha256()
    spend_txid_a = spend_psbt.tx.hash
    man.rpc.setspendtx(spend_txid_a)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx_b)
    spend_psbt.tx.calc_sha256()
    spend_txid_b = spend_psbt.tx.hash
    man.rpc.setspendtx(spend_txid_b)

    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulting"], deposits)["vaults"])
            == len(deposits)
        )
    # We need a single confirmation to consider the Unvault transaction confirmed
    bitcoind.generate_block(1, wait_for_mempool=len(deposits))
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )

    # We'll broadcast the Spend transaction as soon as it's valid
    bitcoind.generate_block(CSV - 1)
    man.wait_for_logs(
        [
            f"Succesfully broadcasted Spend tx '{spend_txid_a}'",
            f"Succesfully broadcasted Spend tx '{spend_txid_b}'",
        ]
    )
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["spending"], deposits)["vaults"])
            == len(deposits)
        )

    # And will mark it as spent after a single confirmation of the Spend tx
    bitcoind.generate_block(1, wait_for_mempool=[spend_txid_a, spend_txid_b])
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_spends_conflicting(revault_network, bitcoind):
    """
    Here we test two spends which spends 2 vaults each, with one shared and all vaults
    being created from the same Deposit transaction.
    """
    # Get some more coins
    bitcoind.generate_block(12)

    CSV = 112
    revault_network.deploy(5, 3, csv=CSV)
    man = revault_network.man(0)
    amounts = [0.1, 64, 410]
    vaults = revault_network.fundmany(amounts)
    assert len(vaults) == len(amounts)
    # Edge case: bitcoind can actually mess up with the amounts
    amounts = []
    deposits = []
    deriv_indexes = []
    for v in vaults:
        revault_network.secure_vault(v)
        revault_network.activate_vault(v)
        deposits.append(f"{v['txid']}:{v['vout']}")
        deriv_indexes.append(v["derivation_index"])
        amounts.append(v["amount"])

    (deposits_a, deposits_b) = (deposits[:2], deposits[1:])
    (amounts_a, amounts_b) = (amounts[:2], amounts[1:])
    (indexes_a, indexes_b) = (deriv_indexes[:2], deriv_indexes[1:])

    feerate = 5_000
    fees = revault_network.compute_spendtx_fees(feerate, len(deposits_a), 1)
    destinations = {bitcoind.rpc.getnewaddress(): sum(amounts_a) - fees}
    spend_tx_a = man.rpc.getspendtx(deposits_a, destinations, 1)["spend_tx"]
    for man in revault_network.mans():
        spend_tx_a = man.man_keychain.sign_spend_psbt(spend_tx_a, indexes_a)
    man.rpc.updatespendtx(spend_tx_a)

    feerate = 10_000
    fees = revault_network.compute_spendtx_fees(feerate, len(deposits_b), 1, True)
    destinations = {bitcoind.rpc.getnewaddress(): (sum(amounts_b) - fees) // 2}
    spend_tx_b = man.rpc.getspendtx(deposits_b, destinations, 1)["spend_tx"]
    for man in revault_network.mans():
        spend_tx_b = man.man_keychain.sign_spend_psbt(spend_tx_b, indexes_b)
    man.rpc.updatespendtx(spend_tx_b)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx_a)
    spend_psbt.tx.calc_sha256()
    spend_txid_a = spend_psbt.tx.hash
    man.rpc.setspendtx(spend_txid_a)

    # We can ask the Cosigning Servers their signature again for the very same Spend
    man.rpc.setspendtx(spend_txid_a)

    # The two Spend have conflicting inputs, therefore the Cosigning Server won't
    # accept to sign the second one.
    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx_b)
    spend_psbt.tx.calc_sha256()
    with pytest.raises(
        RpcError,
        match="one Cosigning Server already signed a Spend transaction spending one of these vaults",
    ):
        man.rpc.setspendtx(spend_psbt.tx.hash)

    wait_for(
        lambda: len(man.rpc.listvaults(["unvaulting"], deposits_a)["vaults"])
        == len(deposits_a)
    )
    # We need a single confirmation to consider the Unvault transaction confirmed
    bitcoind.generate_block(1, wait_for_mempool=len(deposits_a))
    wait_for(
        lambda: len(man.rpc.listvaults(["unvaulted"], deposits_a)["vaults"])
        == len(deposits_a)
    )

    # We'll broadcast the Spend transaction as soon as it's valid
    bitcoind.generate_block(CSV - 1)
    man.wait_for_log(
        f"Succesfully broadcasted Spend tx '{spend_txid_a}'",
    )
    wait_for(
        lambda: len(man.rpc.listvaults(["spending"], deposits_a)["vaults"])
        == len(deposits_a)
    )

    # And will mark it as spent after a single confirmation of the Spend tx
    bitcoind.generate_block(1, wait_for_mempool=[spend_txid_a])
    wait_for(
        lambda: len(man.rpc.listvaults(["spent"], deposits)["vaults"])
        == len(deposits_a)
    )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_spend_threshold(revault_network, bitcoind, executor):
    CSV = 20
    managers_threshold = 3
    revault_network.deploy(17, 8, csv=CSV, managers_threshold=managers_threshold)
    man = revault_network.man(0)

    # Get some more funds
    bitcoind.generate_block(1)

    vaults = []
    deposits = []
    deriv_indexes = []
    total_amount = 0
    for i in range(5):
        amount = random.randint(5, 5000) / 100
        vaults.append(revault_network.fund(amount))
        deposits.append(f"{vaults[i]['txid']}:{vaults[i]['vout']}")
        deriv_indexes.append(vaults[i]["derivation_index"])
        total_amount += vaults[i]["amount"]
    revault_network.activate_fresh_vaults(vaults)

    feerate = 1
    n_outputs = 3
    fees = revault_network.compute_spendtx_fees(feerate, len(deposits), n_outputs)
    destinations = {
        bitcoind.rpc.getnewaddress(): (total_amount - fees) // n_outputs
        for _ in range(n_outputs)
    }
    spend_tx = man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"]

    # Trying to broadcast when managers_threshold - 1 managers signed
    for man in revault_network.mans()[: managers_threshold - 1]:
        spend_tx = man.man_keychain.sign_spend_psbt(spend_tx, deriv_indexes)
    man.rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()

    # Revaultd didn't like it
    with pytest.raises(
        RpcError,
        match=f"Not enough signatures, needed: {managers_threshold}, current: {managers_threshold - 1}'",
    ):
        man.rpc.setspendtx(spend_psbt.tx.hash)

    # Killing the daemon and restart shouldn't cause any issue
    for m in revault_network.mans():
        m.stop()
        m.start()

    # Alright, I'll make the last manager sign...
    man = revault_network.mans()[managers_threshold]
    spend_tx = man.man_keychain.sign_spend_psbt(spend_tx, deriv_indexes)
    man.rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()

    # All good now?
    man.rpc.setspendtx(spend_psbt.tx.hash)

    for m in revault_network.mans():
        wait_for(
            lambda: len(m.rpc.listvaults(["unvaulting"], deposits)["vaults"])
            == len(deposits)
        )

    # Killing the daemon and restart it while unvaulting shouldn't cause
    # any issue
    for m in revault_network.mans():
        m.stop()
        m.start()

    # We need a single confirmation to consider the Unvault transaction confirmed
    bitcoind.generate_block(1, wait_for_mempool=len(deposits))
    for m in revault_network.mans():
        wait_for(
            lambda: len(m.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )

    # We'll broadcast the Spend transaction as soon as it's valid
    bitcoind.generate_block(CSV)
    man.wait_for_log(
        f"Succesfully broadcasted Spend tx '{spend_psbt.tx.hash}'",
    )
    for m in revault_network.mans():
        wait_for(
            lambda: len(m.rpc.listvaults(["spending"], deposits)["vaults"])
            == len(deposits)
        )

    # And will mark it as spent after a single confirmation of the Spend tx
    bitcoind.generate_block(1, wait_for_mempool=[spend_psbt.tx.hash])
    for m in revault_network.mans():
        wait_for(
            lambda: len(m.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_large_spends(revault_network, bitcoind, executor):
    CSV = 2016  # 2 weeks :tm:
    revault_network.deploy(17, 8, csv=CSV)
    man = revault_network.man(0)

    # Get some more funds
    bitcoind.generate_block(1)

    vaults = []
    deposits = []
    deriv_indexes = []
    total_amount = 0
    for i in range(10):
        amount = random.randint(5, 5000) / 100
        vaults.append(revault_network.fund(amount))
        deposits.append(f"{vaults[i]['txid']}:{vaults[i]['vout']}")
        deriv_indexes.append(vaults[i]["derivation_index"])
        total_amount += vaults[i]["amount"]
    revault_network.activate_fresh_vaults(vaults)

    feerate = 1
    n_outputs = random.randint(1, 3)
    fees = revault_network.compute_spendtx_fees(feerate, len(deposits), n_outputs)
    destinations = {
        bitcoind.rpc.getnewaddress(): (total_amount - fees) // n_outputs
        for _ in range(n_outputs)
    }
    spend_tx = man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"]

    for man in revault_network.mans():
        spend_tx = man.man_keychain.sign_spend_psbt(spend_tx, deriv_indexes)
    man.rpc.updatespendtx(spend_tx)

    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    man.rpc.setspendtx(spend_psbt.tx.hash)

    # Killing the daemon and restart it while unvaulting shouldn't cause
    # any issue
    for man in revault_network.mans():
        man.stop()
        man.start()

    wait_for(
        lambda: len(man.rpc.listvaults(["unvaulting"], deposits)["vaults"])
        == len(deposits)
    )
    # We need a single confirmation to consider the Unvault transaction confirmed
    bitcoind.generate_block(1, wait_for_mempool=len(deposits))
    wait_for(
        lambda: len(man.rpc.listvaults(["unvaulted"], deposits)["vaults"])
        == len(deposits)
    )

    # We'll broadcast the Spend transaction as soon as it's valid
    # Note that bitcoind's RPC socket may timeout if it needs to generate too many
    # blocks at once. So, spread them a bit.
    for _ in range(10):
        bitcoind.generate_block(CSV // 10)
    bitcoind.generate_block(CSV % 10 - 1)
    man.wait_for_log(
        f"Succesfully broadcasted Spend tx '{spend_psbt.tx.hash}'",
    )
    wait_for(
        lambda: len(man.rpc.listvaults(["spending"], deposits)["vaults"])
        == len(deposits)
    )

    # And will mark it as spent after a single confirmation of the Spend tx
    bitcoind.generate_block(1, wait_for_mempool=[spend_psbt.tx.hash])
    wait_for(
        lambda: len(man.rpc.listvaults(["spent"], deposits)["vaults"]) == len(deposits)
    )


# Tests that getspendtx returns an error when trying to build a spend too big
# (it wouldn't be possible to announce it to the coordinator when fully signed)
@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_not_announceable_spend(revault_network, bitcoind, executor):
    CSV = 2
    revault_network.deploy(5, 7, csv=CSV)
    man = revault_network.man(0)

    vaults = []
    deposits = []
    deriv_indexes = []
    amounts = [(i + 1) / 100 for i in range(20)]
    total_amount = sum(amounts) * COIN
    vaults = revault_network.fundmany(amounts)
    deposits = [f"{v['txid']}:{v['vout']}" for v in vaults]
    deriv_indexes = [v["derivation_index"] for v in vaults]
    revault_network.activate_fresh_vaults(vaults)

    feerate = 1
    n_outputs = 588
    fees = revault_network.compute_spendtx_fees(feerate, len(deposits), n_outputs)
    output_value = int((total_amount - fees) // n_outputs)
    destinations = {
        bitcoind.rpc.getnewaddress(): output_value for _ in range(n_outputs)
    }

    # Hey, this spend is huge!
    with pytest.raises(
        RpcError, match="Spend transaction is too large, try spending less outpoints'"
    ):
        man.rpc.getspendtx(deposits, destinations, feerate)

    # One less spent outpoint is ok though
    deposits.pop()
    deriv_indexes.pop()
    amounts.pop()
    total_amount = sum(amounts) * COIN
    fees = revault_network.compute_spendtx_fees(feerate, len(deposits), n_outputs)
    output_value = int((total_amount - fees) // n_outputs)
    for addr in destinations:
        destinations[addr] = output_value
    spend_tx = man.rpc.getspendtx(deposits, destinations, feerate)["spend_tx"]
    for man in revault_network.mans():
        spend_tx = man.man_keychain.sign_spend_psbt(spend_tx, deriv_indexes)
        man.rpc.updatespendtx(spend_tx)
    spend_psbt = serializations.PSBT()
    spend_psbt.deserialize(spend_tx)
    spend_psbt.tx.calc_sha256()
    spend_txid = spend_psbt.tx.hash
    man.rpc.setspendtx(spend_txid)

    wait_for(
        lambda: len(man.rpc.listvaults(["unvaulting"], deposits)["vaults"])
        == len(deposits)
    )
    # We need a single confirmation to consider the Unvault transaction confirmed
    bitcoind.generate_block(1, wait_for_mempool=len(deposits))
    wait_for(
        lambda: len(man.rpc.listvaults(["unvaulted"], deposits)["vaults"])
        == len(deposits)
    )

    # We'll broadcast the Spend transaction as soon as it's valid
    bitcoind.generate_block(CSV)
    man.wait_for_log(f"Succesfully broadcasted Spend tx '{spend_txid}'")
    wait_for(
        lambda: len(man.rpc.listvaults(["spending"], deposits)["vaults"])
        == len(deposits)
    )

    # And will mark it as spent after a single confirmation of the Spend tx
    bitcoind.generate_block(1, wait_for_mempool=[spend_psbt.tx.hash])
    wait_for(
        lambda: len(man.rpc.listvaults(["spent"], deposits)["vaults"]) == len(deposits)
    )


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_revaulted_spend(revault_network, bitcoind, executor):
    """
    Revault an ongoing Spend transaction carried out by the managers, under misc
    circumstances.
    """
    CSV = 12
    revault_network.deploy(2, 2, n_stkmanagers=1, csv=CSV)
    mans = revault_network.mans()
    stks = revault_network.stks()

    # Simple case. Managers Spend a single vault.
    vault = revault_network.fund(0.05)
    revault_network.secure_vault(vault)
    revault_network.activate_vault(vault)

    revault_network.spend_vaults_anyhow_unconfirmed([vault])
    revault_network.cancel_vault(vault)

    # Managers spend two vaults, both are canceled.
    vaults = [revault_network.fund(0.05), revault_network.fund(0.1)]
    for v in vaults:
        revault_network.secure_vault(v)
        revault_network.activate_vault(v)

    revault_network.unvault_vaults_anyhow(vaults)
    for vault in vaults:
        revault_network.cancel_vault(vault)

    # Managers spend three vaults, only a single one is canceled. And both of them were
    # created in the same deposit transaction.
    vaults = revault_network.fundmany([0.2, 0.08])
    vaults.append(revault_network.fund(0.03))
    for v in vaults:
        revault_network.secure_vault(v)
        revault_network.activate_vault(v)
    revault_network.unvault_vaults_anyhow(vaults)
    revault_network.cancel_vault(vaults[0])

    # vaults[0] is canceled, therefore the Spend transaction is now invalid. The vaults
    # should be marked as unvaulted since they are not being spent anymore.
    deposits = [f"{v['txid']}:{v['vout']}" for v in vaults[1:]]
    for w in mans + stks:
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"])
            == len(deposits)
        )
