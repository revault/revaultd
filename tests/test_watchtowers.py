import pytest

from fixtures import *
from test_framework.utils import (
    POSTGRES_IS_SETUP,
)


@pytest.mark.skipif(not POSTGRES_IS_SETUP, reason="Needs Postgres for servers db")
def test_wt_share_revocation_txs(revault_network, bitcoind):
    """Sanity check that we share the Emergency signature with the watchtower
    when we get all the revovation signatures for a vault.
    """
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
