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


def test_reorged_deposit(revaultd_stakeholder, bitcoind):
    stk = revaultd_stakeholder

    # Create a new deposit
    amount_sent = 42
    addr = stk.rpc.getdepositaddress()["address"]
    bitcoind.rpc.sendtoaddress(addr, amount_sent)
    wait_for(lambda: len(stk.rpc.listvaults()["vaults"]) > 0)

    # Get it confirmed
    vault = stk.rpc.listvaults()["vaults"][0]
    deposit = f"{vault['txid']}:{vault['vout']}"
    bitcoind.generate_block(6, wait_for_mempool=vault["txid"])
    stk.wait_for_deposits([deposit])
    vault = stk.rpc.listvaults()["vaults"][0]

    # Now reorg the last block. This should not affect us, but we should detect
    # it.
    bitcoind.simple_reorg(bitcoind.rpc.getblockcount() - 1)
    stk.wait_for_logs(
        [
            "Detected reorg",
            # 7 because simple_reorg() adds a block
            f"Vault deposit '{deposit}' still has '7' confirmations",
        ]
    )
    stk.wait_for_deposits([deposit])

    # Now actually reorg the deposit. This should not affect us
    bitcoind.simple_reorg(vault["blockheight"])
    stk.wait_for_logs(
        [
            "Detected reorg",
            # 8 because simple_reorg() adds a block
            f"Vault deposit '{deposit}' still has '8' confirmations",
        ]
    )
    stk.wait_for_deposits([deposit])

    # Now reorg the deposit and shift the transaction up 3 blocks, since we are
    # adding an extra one during the reorg we should still have 6 confs and be
    # fine
    bitcoind.simple_reorg(vault["blockheight"], shift=3)
    stk.wait_for_logs(
        [
            "Detected reorg",
            f"Vault deposit '{deposit}' still has '6' confirmations",
        ]
    )
    stk.wait_for_deposits([deposit])

    # Now reorg the deposit and shift the transaction up 2 blocks, since we are
    # adding an extra one during the reorg we should end up with 5 confs, and
    # mark the vault as unconfirmed
    bitcoind.simple_reorg(vault["blockheight"] + 3, shift=2)
    stk.wait_for_logs(
        [
            "Detected reorg",
            f"Vault deposit '{deposit}' ended up with '5' confirmations",
            "Rescan of all vaults in db done.",
        ]
    )
    wait_for(lambda: stk.rpc.listvaults()["vaults"][0]["status"] == "unconfirmed")

    # Reorg it again, it's already unconfirmed so nothing to do, but since we
    # mined a new block it's now confirmed!
    bitcoind.simple_reorg(vault["blockheight"] + 3 + 2)
    stk.wait_for_logs(
        [
            "Detected reorg",
            f"Vault deposit '{deposit}' is already unconfirmed",
            "Rescan of all vaults in db done.",
            f"Vault at {deposit} is now confirmed",
        ]
    )
    wait_for(lambda: stk.rpc.listvaults()["vaults"][0]["status"] == "funded")

    # Now try to completely evict it from the chain with a 6-blocks reorg. We
    # should mark it as unconfirmed (but it's not the same codepath).
    bitcoind.simple_reorg(vault["blockheight"] + 3 + 2, shift=-1)
    stk.wait_for_logs(
        [
            "Detected reorg",
            f"Vault deposit '{deposit}' ended up without confirmation",
            "Rescan of all vaults in db done.",
        ]
    )
    wait_for(lambda: stk.rpc.listvaults()["vaults"][0]["status"] == "unconfirmed")


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_reorged_deposit_status(revault_network, bitcoind):
    # A csv of 2 because bitcoind would discard updating the mempool if the reorg is >10
    # blocks long.
    revault_network.deploy(4, 2, csv=2, with_watchtowers=False)
    vault = revault_network.fund(0.14)
    revault_network.secure_vault(vault)
    deposit = f"{vault['txid']}:{vault['vout']}"

    # Reorg the deposit. This should not affect us as the transaction did not
    # shift
    bitcoind.simple_reorg(vault["blockheight"])
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                # 7 because simple_reorg() adds a block
                f"Vault deposit '{deposit}' still has '7' confirmations",
            ]
        )

    # Now actually shift it (7 + 1 - 3 == 5)
    bitcoind.simple_reorg(vault["blockheight"], shift=3)
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' ended up with '5' confirmations",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: len(w.rpc.listvaults(["unconfirmed"], [deposit])) == 1)

    # All presigned transactions must have been removed from the db,
    # if we get it confirmed again, it will re-create the pre-signed
    # transactions. But they are the very same than previously to the
    # signatures on the coordinator are still valid therefore the signature
    # fetcher thread will add them all and the vault will be back to 'secured'
    # again
    bitcoind.generate_block(1)
    for w in revault_network.participants():
        w.wait_for_secured_vaults([deposit])

    # TODO: eventually try with tx malleation

    # Now do the same dance with the 'active' status
    revault_network.activate_vault(vault)
    bitcoind.simple_reorg(vault["blockheight"] + 3)
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                # 7 because simple_reorg() adds a block
                f"Vault deposit '{deposit}' still has '7' confirmations",
            ]
        )
    bitcoind.simple_reorg(vault["blockheight"] + 3, shift=3)
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' ended up with '5' confirmations",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: len(w.rpc.listvaults(["unconfirmed"], [deposit])) > 0)
    bitcoind.generate_block(1)
    for w in revault_network.participants():
        w.wait_for_active_vaults([deposit])

    # If we are stopped during the reorg, we recover in the same way at startup
    revault_network.stop_wallets()
    bitcoind.simple_reorg(vault["blockheight"] + 3 + 3)
    revault_network.start_wallets()
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                # 7 because simple_reorg() adds a block
                f"Vault deposit '{deposit}' still has '7' confirmations",
            ]
        )

    revault_network.stop_wallets()
    bitcoind.simple_reorg(vault["blockheight"] + 3 + 3, shift=3)
    revault_network.start_wallets()
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' ended up with '5' confirmations",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: len(w.rpc.listvaults(["unconfirmed"], [deposit])) > 0)
    revault_network.stop_wallets()
    bitcoind.generate_block(1)
    revault_network.start_wallets()
    for w in revault_network.participants():
        w.wait_for_active_vaults([deposit])

    # Now do the same dance with a spent vault

    # Keep track of the deposit transaction for later use as we'll reorg deeply enough that
    # bitcoind won't add the transactions back to mempool.
    deposit_tx = revault_network.stk(0).rpc.listonchaintransactions([deposit])[
        "onchain_transactions"
    ][0]["deposit"]["hex"]

    # If the deposit is not unconfirmed, it's fine
    revault_network.spend_vaults_anyhow([vault])
    for w in revault_network.mans():
        assert len(w.rpc.listspendtxs()["spend_txs"]) == 1
    bitcoind.simple_reorg(vault["blockheight"] + 3 + 3 + 3)
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' still has .* confirmations",
                "Rescan of all vaults in db done.",
            ]
        )

    # If it is then we'll mark it back as unvaulting
    bitcoind.simple_reorg(vault["blockheight"] + 3 + 3 + 3, shift=-1)
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' ended up without confirmation",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: len(w.rpc.listvaults(["unvaulting"])["vaults"]) == 1)

    # Now the same dance with a canceled vault

    # Re-confirm the vault, get it active, then unvault and cancel it.
    bitcoind.rpc.sendrawtransaction(deposit_tx)
    bitcoind.generate_block(1, wait_for_mempool=2)
    vault = revault_network.stk(0).rpc.listvaults(
        # NB: 'unvaulting' because we reuse a vault that was previously spent! (ie
        # the Spend transaction is in the walelt and therefore we don't keep track
        # of the Unvault confirmation)
        ["unvaulting"]
    )["vaults"][0]
    revault_network.cancel_vault(vault)

    # If the deposit is not unconfirmed, nothing changes
    bitcoind.simple_reorg(vault["blockheight"], shift=2)
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' still has .* confirmations",
                "Rescan of all vaults in db done.",
            ]
        )

    # If it is then it'll be marked as 'canceling'
    logging.debug(f"Before block count {bitcoind.rpc.getblockcount()}")
    bitcoind.simple_reorg(vault["blockheight"] + 2, shift=-1)
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault deposit '{deposit}' ended up without confirmation",
                "Rescan of all vaults in db done.",
            ]
        )
        wait_for(lambda: len(w.rpc.listvaults(["canceling"])["vaults"]) == 1)

    # Now the same dance with an emergencied vault
    # TODO


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_reorged_unvault(revault_network, bitcoind):
    revault_network.deploy(4, 2, csv=12, with_watchtowers=False)
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

    unvault_tx_a = man.rpc.listonchaintransactions([deposits[0]])[
        "onchain_transactions"
    ][0]["unvault"]
    unvault_tx_b = man.rpc.listonchaintransactions([deposits[1]])[
        "onchain_transactions"
    ][0]["unvault"]

    # If the Unvault moves but it still confirmed, everything is fine :tm:
    assert unvault_tx_a["blockheight"] == unvault_tx_b["blockheight"]
    for w in revault_network.participants():
        assert len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"]) == len(deposits)
    bitcoind.simple_reorg(unvault_tx_a["blockheight"], shift=1)
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposits[0]}'s Unvault transaction is still confirmed",
                f"Vault {deposits[1]}'s Unvault transaction is still confirmed",
                "Rescan of all vaults in db done.",
            ]
        )
    for w in revault_network.participants():
        assert len(w.rpc.listvaults(["unvaulted"], deposits)["vaults"]) == len(deposits)

    # If it's not confirmed anymore, we'll detect it and mark the vault as unvaulting
    bitcoind.simple_reorg(unvault_tx_a["blockheight"] + 1, shift=-1)
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
        assert len(w.rpc.listvaults(["unvaulting"], deposits)["vaults"]) == len(
            deposits
        )

    # Now if we are spending
    # unvault_vault() above actually registered the Spend transaction, so we can activate
    # it by generating enough block for it to be mature.
    bitcoind.generate_block(1, wait_for_mempool=len(vaults))
    bitcoind.generate_block(revault_network.csv - 1)
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["spending"], deposits)["vaults"])
            == len(deposits)
        )

    # If we are 'spending' and the Unvault gets unconfirmed, it'll get marked for
    # re-broadcast
    bitcoind.simple_reorg(unvault_tx_a["blockheight"] + 1, shift=-1)
    for w in revault_network.participants():
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposits[0]}'s Unvault transaction .* got unconfirmed",
                f"Vault {deposits[1]}'s Unvault transaction .* got unconfirmed",
                "Rescan of all vaults in db done.",
            ]
        )
    # NOTE: it will stay in the 'unvaulting' state until it can finally gets marked as
    # 'spending' (ie once the Spend transaction is valid and can be in mempool). That's
    # because bitcoind's wallet will consider the Unvault at spent even if it's actually
    # 'spent' by a yet-invalid transaction, and this prevents us to track confirmation.
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["unvaulting"], deposits)["vaults"])
            == len(deposits)
        )
    bitcoind.generate_block(1, wait_for_mempool=len(vaults))
    bitcoind.generate_block(revault_network.csv - 1)
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["spending"], deposits)["vaults"])
            == len(deposits)
        )
    bitcoind.generate_block(1, wait_for_mempool=1)
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )

    # If we are 'spent' and the Unvault gets unconfirmed, it'll get marked for
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
    bitcoind.generate_block(1, wait_for_mempool=1)
    for w in revault_network.participants():
        wait_for(
            lambda: len(w.rpc.listvaults(["spent"], deposits)["vaults"])
            == len(deposits)
        )


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

    # Reorging, but not unconfirming the cancel
    bitcoind.simple_reorg(cancel_tx["blockheight"])
    for w in stks + mans:
        w.wait_for_logs(
            [
                "Detected reorg",
                f"Vault {deposit}'s Cancel transaction is still confirmed",
                "Rescan of all vaults in db done.",
            ]
        )

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
    for w in stks + mans:
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"]
            == "canceling"
        )

    # Confirming the cancel again
    bitcoind.generate_block(1, wait_for_mempool=1)
    for w in stks + mans:
        w.wait_for_log("Cancel tx .* was confirmed at height .*")
        wait_for(
            lambda: w.rpc.listvaults([], [deposit])["vaults"][0]["status"] == "canceled"
        )

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
