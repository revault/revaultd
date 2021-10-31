import pytest

from fixtures import *
from test_framework.utils import (
    POSTGRES_IS_SETUP,
)


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
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

    rn.activate_vault(v)
    for stk in rn.stks():
        stk.watchtower.wait_for_logs(
            [
                f"Got UnEmer transaction signatures for vault at '{deposit}'",
                f"Got Cancel transaction signatures for vault at '{deposit}'."
                " Now watching for Unvault broadcast.",
            ]
        )
