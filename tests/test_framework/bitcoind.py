import decimal
import json
import logging
import os
import threading

from cheroot.wsgi import PathInfoDispatcher, Server
from decimal import Decimal
from ephemeral_port_reserve import reserve
from flask import Flask, request, Response
from test_framework.authproxy import AuthServiceProxy, JSONRPCException
from test_framework.utils import TailableProc, wait_for, TIMEOUT, BITCOIND_PATH, COIN


class BitcoindRpcInterface:
    def __init__(self, data_dir, network, rpc_port):
        self.cookie_path = os.path.join(data_dir, network, ".cookie")
        self.rpc_port = rpc_port
        self.wallet_name = "revaultd-tests"

    def __getattr__(self, name):
        assert not (name.startswith("__") and name.endswith("__")), "Python internals"

        with open(self.cookie_path) as fd:
            authpair = fd.read()
        service_url = (
            f"http://{authpair}@localhost:{self.rpc_port}/wallet/{self.wallet_name}"
        )
        proxy = AuthServiceProxy(service_url, name)

        def f(*args):
            return proxy.__call__(*args)

        # Make debuggers show <function bitcoin.rpc.name> rather than <function
        # bitcoin.rpc.<lambda>>
        f.__name__ = name
        return f


class BitcoinD(TailableProc):
    def __init__(self, bitcoin_dir, rpcport=None):
        TailableProc.__init__(self, bitcoin_dir, verbose=False)

        if rpcport is None:
            rpcport = reserve()

        self.bitcoin_dir = bitcoin_dir
        self.rpcport = rpcport
        self.p2pport = reserve()
        self.prefix = "bitcoind"

        regtestdir = os.path.join(bitcoin_dir, "regtest")
        if not os.path.exists(regtestdir):
            os.makedirs(regtestdir)

        self.cmd_line = [
            BITCOIND_PATH,
            "-datadir={}".format(bitcoin_dir),
            "-printtoconsole",
            "-server",
        ]
        bitcoind_conf = {
            "port": self.p2pport,
            "rpcport": rpcport,
            "debug": 1,
            "fallbackfee": Decimal(1000) / COIN,
            "rpcthreads": 32,
        }
        self.conf_file = os.path.join(bitcoin_dir, "bitcoin.conf")
        with open(self.conf_file, "w") as f:
            f.write("chain=regtest\n")
            f.write("[regtest]\n")
            for k, v in bitcoind_conf.items():
                f.write(f"{k}={v}\n")

        self.rpc = BitcoindRpcInterface(bitcoin_dir, "regtest", rpcport)

    def start(self):
        TailableProc.start(self)
        self.wait_for_log("Done loading", timeout=TIMEOUT)

        logging.info("BitcoinD started")

    def stop(self):
        for p in self.proxies:
            p.stop()
        self.rpc.stop()
        return TailableProc.stop(self)

    # wait_for_mempool can be used to wait for the mempool before generating
    # blocks:
    # True := wait for at least 1 transation
    # int > 0 := wait for at least N transactions
    # 'tx_id' := wait for one transaction id given as a string
    # ['tx_id1', 'tx_id2'] := wait until all of the specified transaction IDs
    def generate_block(self, numblocks=1, wait_for_mempool=0):
        if wait_for_mempool:
            if isinstance(wait_for_mempool, str):
                wait_for_mempool = [wait_for_mempool]
            if isinstance(wait_for_mempool, list):
                wait_for(
                    lambda: all(
                        txid in self.rpc.getrawmempool() for txid in wait_for_mempool
                    )
                )
            else:
                wait_for(lambda: len(self.rpc.getrawmempool()) >= wait_for_mempool)

        old_blockcount = self.rpc.getblockcount()
        addr = self.rpc.getnewaddress()
        self.rpc.generatetoaddress(numblocks, addr)
        wait_for(lambda: self.rpc.getblockcount() == old_blockcount + numblocks)

    def get_coins(self, amount_btc):
        # subsidy halving is every 150 blocks on regtest, it's a rough estimate
        # to avoid looping in most cases
        numblocks = amount_btc // 25 + 1
        while self.rpc.getbalance() < amount_btc:
            self.generate_block(numblocks)

    def generate_blocks_censor(self, n, txids):
        """Generate {n} blocks ignoring {txids}"""
        fee_delta = 1000000
        for txid in txids:
            self.rpc.prioritisetransaction(txid, None, -fee_delta)
        self.generate_block(n)
        for txid in txids:
            self.rpc.prioritisetransaction(txid, None, fee_delta)

    def generate_empty_blocks(self, n):
        """Generate {n} empty blocks"""
        addr = self.rpc.getnewaddress()
        for _ in range(n):
            self.rpc.generateblock(addr, [])

    def simple_reorg(self, height, shift=0):
        """
        Reorganize chain by creating a fork at height={height} and:
            - If shift >=0:
                - re-mine all mempool transactions into {height} + shift
                  (with shift floored at 1)
            - Else:
                - don't re-mine the mempool transactions

        Note that tx's that become invalid at {height} (because coin maturity,
        locktime etc.) are removed from mempool. The length of the new chain
        will be original + 1 OR original + {shift}, whichever is larger.

        For example: to push tx's backward from height h1 to h2 < h1,
        use {height}=h2.

        Or to change the txindex of tx's at height h1:
        1. A block at height h2 < h1 should contain a non-coinbase tx that can
            be pulled forward to h1.
        2. Set {height}=h2 and {shift}= h1-h2
        """
        orig_len = self.rpc.getblockcount()
        old_hash = self.rpc.getblockhash(height)
        if height + shift > orig_len:
            final_len = height + shift
        else:
            final_len = 1 + orig_len

        self.rpc.invalidateblock(old_hash)
        self.wait_for_log(
            r"InvalidChainFound: invalid block=.*  height={}".format(height)
        )
        memp = self.rpc.getrawmempool()

        if shift < 0:
            self.generate_empty_blocks(1 + final_len - height)
        elif shift == 0:
            self.generate_block(1 + final_len - height, memp)
        else:
            self.generate_empty_blocks(shift)
            self.generate_block(1 + final_len - (height + shift), memp)
        self.wait_for_log(r"UpdateTip: new best=.* height={}".format(final_len))

    def startup(self):
        try:
            self.start()
        except Exception:
            self.stop()
            raise

        info = self.rpc.getnetworkinfo()
        if info["version"] < 220000:
            self.rpc.stop()
            raise ValueError(
                "bitcoind is too old. Minimum supported version is 0.22.0."
                " Current is {}".format(info["version"])
            )

    def cleanup(self):
        try:
            self.stop()
        except Exception:
            self.proc.kill()
        self.proc.wait()


class DecimalEncoder(json.JSONEncoder):
    """By default json.dumps does not handle Decimals correctly, so we override its handling"""

    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return float(o)
        return super(DecimalEncoder, self).default(o)


class BitcoindRpcProxy(object):
    """A proxy to the bitcoind RPC interface that can replace commands with arbitrary results.

    Starts a HTTP server in a thread, listens for incoming JSONRPC requests, and responds with
    either a mocked result or the result it got from bitcoind.
    This was taken and adapted from the C-lightning test suite.
    """

    def __init__(self, bitcoind_rpc_port, bitcoind_cookie_path, mocks):
        self.app = Flask("BitcoindProxy")
        self.app.add_url_rule(
            "/",
            "Entrypoint",
            self.proxy,
            methods=["POST"],
            defaults={"path": ""},
        )
        self.app.add_url_rule(
            "/<path:path>",
            "Entrypoint",
            self.proxy,
            methods=["POST"],
        )
        self.rpcport = reserve()
        # A mapping from method name to result as a dict.
        # Eventually, the results could be callable.
        self.mocks = mocks
        self.bitcoind_rpc_port = bitcoind_rpc_port
        self.bitcoind_cookie_path = bitcoind_cookie_path

        self.start()

    def __del__(self):
        self.stop()

    def _handle_request(self, r, path):
        """Handle a JSONRPC request {r} made to the HTTP endpoint {path} (to handle
        wallet paths)"""
        method = r["method"]

        # If we have set a mock for this method reply with that
        if method in self.mocks:
            return {"id": r["id"], "error": None, "result": self.mocks[method]}

        # Otherwise, just forward the request
        with open(self.bitcoind_cookie_path) as fd:
            authpair = fd.read()
        service_url = f"http://{authpair}@localhost:{self.bitcoind_rpc_port}/{path}"

        try:
            res = AuthServiceProxy(service_url, r["method"])(*r["params"])
            return {"result": res, "id": r["id"]}
        except JSONRPCException as e:
            return {"error": e.error, "id": r["id"]}

    def proxy(self, path):
        r = json.loads(request.data.decode("ASCII"))

        if isinstance(r, list):
            reply = [self._handle_request(subreq, path) for subreq in r]
        else:
            reply = self._handle_request(r, path)

        # \r\n because rust-jsonrpc expects it..
        response = Response(json.dumps(reply, cls=DecimalEncoder) + "\r\n")
        response.headers["Content-Type"] = "application/json"
        return response

    def start(self):
        self.server = Server(
            ("127.0.0.1", self.rpcport),
            self.app,
            numthreads=32,
            request_queue_size=10,
            accepted_queue_timeout=20,
            timeout=TIMEOUT * 2,
        )
        self.proxy_thread = threading.Thread(target=self.server.start)
        self.proxy_thread.daemon = True
        self.proxy_thread.start()

        # Now that bitcoind is running on the real rpcport, let's tell all
        # future callers to talk to the proxyport. We use the bind_addr as a
        # signal that the port is bound and accepting connections.
        while self.server.bind_addr[1] == 0:
            pass
        self.rpcport = self.server.bind_addr[1]

    def stop(self):
        self.server.stop()
        self.proxy_thread.join()
