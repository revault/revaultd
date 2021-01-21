"""
Most of the code here is stolen from C-lightning's test suite. This is surely
Rusty Russell or Christian Decker who wrote most of this (I'd put some sats on
cdecker), so credits to them ! (MIT licensed)
"""
from bitcoin.rpc import RawProxy as BitcoinProxy
from decimal import Decimal
from ephemeral_port_reserve import reserve
from typing import Optional

import bip32
import bitcoin
import json
import logging
import os
import random
import re
import select
import socket
import subprocess
import threading
import time


TIMEOUT = int(os.getenv("TIMEOUT", 60))
TEST_DEBUG = os.getenv("TEST_DEBUG", "0") == "1"


def wait_for(success, timeout=TIMEOUT):
    start_time = time.time()
    interval = 0.25
    while not success() and time.time() < start_time + timeout:
        time.sleep(interval)
        interval *= 2
        if interval > 5:
            interval = 5
    if time.time() > start_time + timeout:
        raise ValueError("Error waiting for {}", success)


class RpcError(ValueError):
    def __init__(self, method: str, payload: dict, error: str):
        super(ValueError, self).__init__(
            "RPC call failed: method: {}, payload: {}, error: {}".format(
                method, payload, error
            )
        )

        self.method = method
        self.payload = payload
        self.error = error


def get_participants(n_stk, n_man):
    """Get the configuration entries for each participant."""
    stakeholders_xpubs = [
        bip32.BIP32.from_seed(os.urandom(32)).get_master_xpub()
        for _ in range(n_stk)
    ]
    cosigners_keys = [
        bip32.BIP32.from_seed(os.urandom(32)).get_pubkey_from_path("m/0").hex()
        for _ in range(n_stk)
    ]
    managers_xpubs = [
        bip32.BIP32.from_seed(os.urandom(32)).get_master_xpub()
        for _ in range(n_man)
    ]

    return (stakeholders_xpubs, cosigners_keys, managers_xpubs)


class UnixSocket(object):
    """A wrapper for socket.socket that is specialized to unix sockets.

    Some OS implementations impose restrictions on the Unix sockets.

     - On linux OSs the socket path must be shorter than the in-kernel buffer
       size (somewhere around 100 bytes), thus long paths may end up failing
       the `socket.connect` call.

    This is a small wrapper that tries to work around these limitations.

    """

    def __init__(self, path: str):
        self.path = path
        self.sock: Optional[socket.SocketType] = None
        self.connect()

    def connect(self) -> None:
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.path)
        except OSError as e:
            self.close()

            if (e.args[0] == "AF_UNIX path too long" and os.uname()[0] == "Linux"):
                # If this is a Linux system we may be able to work around this
                # issue by opening our directory and using `/proc/self/fd/` to
                # get a short alias for the socket file.
                #
                # This was heavily inspired by the Open vSwitch code see here:
                # https://github.com/openvswitch/ovs/blob/master/python/ovs/socket_util.py

                dirname = os.path.dirname(self.path)
                basename = os.path.basename(self.path)

                # Open an fd to our home directory, that we can then find
                # through `/proc/self/fd` and access the contents.
                dirfd = os.open(dirname, os.O_DIRECTORY | os.O_RDONLY)
                short_path = "/proc/self/fd/%d/%s" % (dirfd, basename)
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(short_path)
            else:
                # There is no good way to recover from this.
                raise

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
        self.sock = None

    def sendall(self, b: bytes) -> None:
        if self.sock is None:
            raise socket.error("not connected")

        self.sock.sendall(b)

    def recv(self, length: int) -> bytes:
        if self.sock is None:
            raise socket.error("not connected")

        return self.sock.recv(length)

    def __del__(self) -> None:
        self.close()


class UnixDomainSocketRpc(object):
    def __init__(self, socket_path, logger=logging):
        self.socket_path = socket_path
        self.logger = logger
        self.next_id = 0

    def _writeobj(self, sock, obj):
        s = json.dumps(obj, ensure_ascii=False)
        sock.sock.sendall(s.encode())

    def _readobj(self, sock):
        """Read a JSON object"""
        buff = b""
        while True:
            n_to_read = max(2048, len(buff))
            chunk = sock.recv(n_to_read)
            buff += chunk
            if len(chunk) != n_to_read:
                print("Got: {}", buff)
                return json.loads(buff)

    def __getattr__(self, name):
        """Intercept any call that is not explicitly defined and call @call.

        We might still want to define the actual methods in the subclasses for
        documentation purposes.
        """
        name = name.replace('_', '-')

        def wrapper(*args, **kwargs):
            if len(args) != 0 and len(kwargs) != 0:
                raise RpcError(name, {}, "Cannot mix positional and non-positional arguments")
            elif len(args) != 0:
                return self.call(name, payload=args)
            else:
                return self.call(name, payload=list(kwargs.values()))
        return wrapper

    # FIXME: support named parameters on the Rust server!
    def call(self, method, payload=[]):
        self.logger.debug("Calling %s with payload %r", method, payload)

        # FIXME: we open a new socket for every readobj call...
        sock = UnixSocket(self.socket_path)
        msg = json.dumps({
            "jsonrpc": "2.0",
            "id": 0,
            "method": method,
            "params": payload,
        })
        sock.sock.send(msg.encode())
        this_id = self.next_id
        resp = self._readobj(sock)

        self.logger.debug("Received response for %s call: %r", method, resp)
        if 'id' in resp and resp['id'] != this_id:
            raise ValueError("Malformed response, id is not {}: {}.".format(this_id, resp))
        sock.close()

        if not isinstance(resp, dict):
            raise ValueError("Malformed response, response is not a dictionary %s." % resp)
        elif "error" in resp:
            raise RpcError(method, payload, resp['error'])
        elif "result" not in resp:
            raise ValueError("Malformed response, \"result\" missing.")
        return resp["result"]


class TailableProc(object):
    """A monitorable process that we can start, stop and tail.

    This is the base class for the daemons. It allows us to directly
    tail the processes and react to their output.
    """

    def __init__(self, outputDir=None, verbose=True):
        self.logs = []
        self.logs_cond = threading.Condition(threading.RLock())
        self.env = os.environ.copy()
        self.running = False
        self.proc = None
        self.outputDir = outputDir
        self.logsearch_start = 0

        # Set by inherited classes
        self.cmd_line = []
        self.prefix = ""

        # Should we be logging lines we read from stdout?
        self.verbose = verbose

        # A filter function that'll tell us whether to filter out the line (not
        # pass it to the log matcher and not print it to stdout).
        self.log_filter = lambda _: False

    def start(self, stdin=None, stdout=None, stderr=None):
        """Start the underlying process and start monitoring it.
        """
        logging.debug("Starting '%s'", " ".join(self.cmd_line))
        self.proc = subprocess.Popen(self.cmd_line,
                                     stdin=stdin,
                                     stdout=stdout if stdout
                                     else subprocess.PIPE,
                                     stderr=stderr,
                                     env=self.env)
        self.thread = threading.Thread(target=self.tail)
        self.thread.daemon = True
        self.thread.start()
        self.running = True

    def save_log(self):
        if self.outputDir:
            logpath = os.path.join(self.outputDir, 'log')
            with open(logpath, 'w') as f:
                for l in self.logs:
                    f.write(l + '\n')

    def stop(self, timeout=10):
        self.save_log()
        self.proc.terminate()

        # Now give it some time to react to the signal
        rc = self.proc.wait(timeout)

        if rc is None:
            self.proc.kill()

        self.proc.wait()
        self.thread.join()

        return self.proc.returncode

    def kill(self):
        """Kill process without giving it warning."""
        self.proc.kill()
        self.proc.wait()
        self.thread.join()

    def tail(self):
        """Tail the stdout of the process and remember it.

        Stores the lines of output produced by the process in
        self.logs and signals that a new line was read so that it can
        be picked up by consumers.
        """
        for line in iter(self.proc.stdout.readline, ''):
            if len(line) == 0:
                break
            if self.log_filter(line.decode('ASCII')):
                continue
            if self.verbose:
                logging.debug(f"{self.prefix}: {line.decode().rstrip()}")
            with self.logs_cond:
                self.logs.append(str(line.rstrip()))
                self.logs_cond.notifyAll()
        self.running = False
        self.proc.stdout.close()
        if self.proc.stderr:
            self.proc.stderr.close()

    def is_in_log(self, regex, start=0):
        """Look for `regex` in the logs."""

        ex = re.compile(regex)
        for l in self.logs[start:]:
            if ex.search(l):
                logging.debug("Found '%s' in logs", regex)
                return l

        logging.debug("Did not find '%s' in logs", regex)
        return None

    def wait_for_logs(self, regexs, timeout=TIMEOUT):
        """Look for `regexs` in the logs.

        We tail the stdout of the process and look for each regex in `regexs`,
        starting from last of the previous waited-for log entries (if any).  We
        fail if the timeout is exceeded or if the underlying process
        exits before all the `regexs` were found.

        If timeout is None, no time-out is applied.
        """
        logging.debug("Waiting for {} in the logs".format(regexs))

        exs = [re.compile(r) for r in regexs]
        start_time = time.time()
        pos = self.logsearch_start

        while True:
            if timeout is not None and time.time() > start_time + timeout:
                print("Time-out: can't find {} in logs".format(exs))
                for r in exs:
                    if self.is_in_log(r):
                        print("({} was previously in logs!)".format(r))
                raise TimeoutError('Unable to find "{}" in logs.'.format(exs))
            elif not self.running:
                raise ValueError('Process died while waiting for logs')

            with self.logs_cond:
                if pos >= len(self.logs):
                    self.logs_cond.wait(1)
                    continue

                for r in exs.copy():
                    self.logsearch_start = pos + 1
                    if r.search(self.logs[pos]):
                        logging.debug("Found '%s' in logs", r)
                        exs.remove(r)
                        break
                if len(exs) == 0:
                    return self.logs[pos]
                pos += 1

    def wait_for_log(self, regex, timeout=TIMEOUT):
        """Look for `regex` in the logs.

        Convenience wrapper for the common case of only seeking a single entry.
        """
        return self.wait_for_logs([regex], timeout)


class SimpleBitcoinProxy:
    """Wrapper for BitcoinProxy to reconnect.

    Long wait times between calls to the Bitcoin RPC could result in
    `bitcoind` closing the connection, so here we just create
    throwaway connections. This is easier than to reach into the RPC
    library to close, reopen and reauth upon failure.
    """
    def __init__(self, bitcoind_dir, bitcoind_port, *args, **kwargs):
        self.__btc_conf_file__ = os.path.join(bitcoind_dir, "bitcoin.conf")
        self.__cookie_path = os.path.join(bitcoind_dir, "regtest", ".cookie")
        self.__port = bitcoind_port
        # The internal bitcoind wallet, used to generate blocks and distribute
        # coins
        self.wallet_name = "revaultd-tests"

    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            # Python internal stuff
            raise AttributeError

        # We want to hit the per-wallet API and python-bitcoinlib will not read
        # the cookie if we specify a custom URL..
        with open(self.__cookie_path) as fd:
            authpair = fd.read()
        service_url = f"http://{authpair}@localhost:{self.__port}/wallet"\
                      f"/{self.wallet_name}"

        # Create a callable to do the actual call
        proxy = BitcoinProxy(btc_conf_file=self.__btc_conf_file__,
                             service_url=service_url)

        def f(*args):
            return proxy._call(name, *args)

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
        self.prefix = 'bitcoind'

        regtestdir = os.path.join(bitcoin_dir, 'regtest')
        if not os.path.exists(regtestdir):
            os.makedirs(regtestdir)

        self.cmd_line = [
            'bitcoind',
            '-datadir={}'.format(bitcoin_dir),
            '-printtoconsole',
            '-server',
            '-logtimestamps',
            '-rpcthreads=4',
        ]
        bitcoind_conf = {
            'port': self.p2pport,
            'rpcport': rpcport,
            'debug': 1,
            'fallbackfee': Decimal(1000) / bitcoin.core.COIN,
        }
        self.conf_file = os.path.join(bitcoin_dir, 'bitcoin.conf')
        with open(self.conf_file, 'w') as f:
            f.write(f"chain=regtest\n")
            f.write(f"[regtest]\n")
            for k, v in bitcoind_conf.items():
                f.write(f"{k}={v}\n")

        self.rpc = SimpleBitcoinProxy(bitcoind_dir=self.bitcoin_dir,
                                      bitcoind_port=self.rpcport)
        self.proxies = []

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
                wait_for(lambda: all(txid in self.rpc.getrawmempool()
                                     for txid in wait_for_mempool))
            else:
                wait_for(lambda: len(self.rpc.getrawmempool())
                         >= wait_for_mempool)

        addr = self.rpc.getnewaddress()
        return self.rpc.generatetoaddress(numblocks, addr)

    def simple_reorg(self, height, shift=0):
        """
        Reorganize chain by creating a fork at height=[height] and re-mine all
        mempool transactions into [height + shift], where shift >= 0. Returns
        hashes of generated blocks.

        Note that tx's that become invalid at [height] (because coin maturity,
        locktime etc.) are removed from mempool. The length of the new chain
        will be original + 1 OR original + [shift], whichever is larger.

        For example: to push tx's backward from height h1 to h2 < h1,
        use [height]=h2.

        Or to change the txindex of tx's at height h1:
        1. A block at height h2 < h1 should contain a non-coinbase tx that can
            be pulled forward to h1.
        2. Set [height]=h2 and [shift]= h1-h2
        """
        hashes = []
        fee_delta = 1000000
        orig_len = self.rpc.getblockcount()
        old_hash = self.rpc.getblockhash(height)
        if height + shift > orig_len:
            final_len = height + shift
        else:
            final_len = 1 + orig_len
        # TODO: raise error for insane args?

        self.rpc.invalidateblock(old_hash)
        self.wait_for_log(r'InvalidChainFound: invalid block=.*  height={}'
                          .format(height))
        memp = self.rpc.getrawmempool()

        if shift == 0:
            hashes += self.generate_block(1 + final_len - height)
        else:
            for txid in memp:
                # lower priority (to effective feerate=0) so they are not mined
                self.rpc.prioritisetransaction(txid, None, -fee_delta)
            hashes += self.generate_block(shift)

            for txid in memp:
                # restore priority so they are mined
                self.rpc.prioritisetransaction(txid, None, fee_delta)
            hashes += self.generate_block(1 + final_len - (height + shift))
        self.wait_for_log(r'UpdateTip: new best=.* height={}'
                          .format(final_len))
        return hashes

    def startup(self):
        try:
            self.start()
        except Exception:
            self.stop()
            raise

        info = self.rpc.getnetworkinfo()

        if info['version'] < 210000:
            self.rpc.stop()
            raise ValueError("bitcoind is too old. At least version 21000"
                             " (v0.21.0) is needed, current version is {}"
                             .format(info['version']))

    def cleanup(self):
        try:
            self.stop()
        except Exception:
            self.proc.kill()
        self.proc.wait()


class RevaultD(TailableProc):
    def __init__(self, datadir, stk_xpubs, cosig_keys, man_xpubs, csv,
                 bitcoind, stk_config=None, man_config=None):
        assert stk_config is not None or man_config is not None
        assert len(stk_xpubs) == len(cosig_keys)

        TailableProc.__init__(self, datadir, verbose=False)
        bin = os.path.join(os.path.dirname(__file__), "..",
                           "target/debug/revaultd")
        self.conf_file = os.path.join(datadir, "config.toml")
        self.cmd_line = [
            bin,
            f"--conf",
            f"{self.conf_file}"
        ]
        self.prefix = "revaultd"
        socket_path = os.path.join(datadir, "regtest", "revaultd_rpc")
        self.rpc = UnixDomainSocketRpc(socket_path)

        bitcoind_cookie = os.path.join(bitcoind.bitcoin_dir, "regtest",
                                       ".cookie")
        with open(self.conf_file, 'w') as f:
            f.write(f"unvault_csv = {csv}\n")
            # FIXME: eventually use a real one here
            f.write("emergency_address = "
                    "\"bcrt1qewc2348370pgw8kjz8gy09z8xyh0d9fxde6nzamd3txc9gkmjqmq8m4cdq\"\n")
            f.write(f"data_dir = '{datadir}'\n")
            f.write(f"daemon = false\n")
            f.write(f"log_level = 'trace'\n")

            # TODO: use a real one
            f.write("coordinator_host = \"127.0.0.1:1\"\n")
            f.write("coordinator_noise_key = "
                    "\"d91563973102454a7830137e92d0548bc83b4ea2799f1df04622ca1307381402\"\n")

            f.write("stakeholders_xpubs = [")
            for xpub in stk_xpubs:
                f.write(f"\"{xpub}\", ")
            f.write("]\n")

            f.write("managers_xpubs = [")
            for xpub in man_xpubs:
                f.write(f"\"{xpub}\", ")
            f.write("]\n")

            f.write("cosigners_keys = [")
            for key in cosig_keys:
                f.write(f"\"{key}\", ")
            f.write("]\n")

            f.write(f"[bitcoind_config]\n")
            f.write(f"network = \"regtest\"\n")
            f.write(f"cookie_path = '{bitcoind_cookie}'\n")
            f.write(f"addr = '127.0.0.1:{bitcoind.rpcport}'\n")

            if stk_config is not None:
                f.write("[stakeholder_config]\n")
                f.write(f"xpub = \"{stk_config['xpub']}\"\n")
                f.write("watchtowers = [")
                for wt in stk_config["watchtowers"]:
                    f.write(f"{{ \"host\" = \"{wt['host']}\", \"noise_key\" = "
                            f"\"{wt['noise_key']}\" }}, ")
                f.write("]\n")

            if man_config is not None:
                f.write("[manager_config]\n")
                f.write(f"xpub = \"{man_config['xpub']}\"\n")
                f.write("cosigners = [")
                for wt in man_config["watchtowers"]:
                    f.write(f"{{ \"host\" = \"{wt['host']}\", \"noise_key\" = "
                            f"\"{wt['noise_key']}\" }}, ")
                f.write("]\n")

    def start(self):
        TailableProc.start(self)
        self.wait_for_logs(["revaultd started on network regtest",
                            "bitcoind now synced",
                            "JSONRPC server started"])

    def cleanup(self):
        self.proc.kill()
        self.proc.wait()


class RevaultDFactory:
    # FIXME: we use a single bitcoind for all the wallets because it's much
    # more efficient. Eventually, we may have to test with separate ones.
    def __init__(self, root_dir, bitcoind):
        self.root_dir = root_dir
        self.bitcoind = bitcoind
        self.daemons = []

    def deploy(self, n_stakeholders, n_managers, funding=None, csv=None):
        """
        Deploy a revault setup with {n_stakeholders} stakeholders, {n_managers}
        managers and optionally fund it with {funding} sats.
        """
        (stk_xpubs, cosig_keys, man_xpubs) = get_participants(n_stakeholders,
                                                              n_managers)
        if csv is None:
            # More than 6 months
            csv = random.randint(1, 26784)

        stk_nodes = []
        for i in range(len(stk_xpubs)):
            datadir = os.path.join(self.root_dir, f"revaultd-stk-{i}")
            os.makedirs(datadir, exist_ok=True)

            stk_config = {
                "xpub": stk_xpubs[i],
                # FIXME: Eventually use real ones
                "watchtowers": [
                    {
                        "host": "127.0.0.1:1",
                        "noise_key": "03c3fee141e97ed33a50875a092179684c1145"
                                     "5cc6f49a9bddaacf93cd77def697"
                    }
                ]
            }
            daemon = RevaultD(datadir, stk_xpubs, cosig_keys, man_xpubs, csv,
                              self.bitcoind, stk_config=stk_config)
            daemon.start()
            stk_nodes.append(daemon)

        man_nodes = []
        for i in range(len(man_xpubs)):
            datadir = os.path.join(self.root_dir, f"revaultd-man-{i}")
            os.makedirs(datadir, exist_ok=True)

            man_config = {
                "xpub": man_xpubs[i],
                # FIXME: Eventually use real ones
                "watchtowers": [
                    {
                        "host": "127.0.0.1:1",
                        "noise_key": "03c3fee141e97ed33a50875a092179684c1145"
                                     "5cc6f49a9bddaacf93cd77def697"
                    }
                ]
            }
            daemon = RevaultD(datadir, stk_xpubs, cosig_keys, man_xpubs, csv,
                              self.bitcoind, man_config=man_config)
            daemon.start()
            man_nodes.append(daemon)

        if funding is not None:
            assert isinstance(funding, int)
            addr = man_nodes[0].rpc.getdepositaddress["address"]
            txid = self.bitcoind.rpc.sendtoaddress(addr, 49.9999)
            self.bitcoind.generate_block(6, wait_for_mempool=txid)

        self.daemons += stk_nodes + man_nodes
        return (stk_nodes, man_nodes)

    def cleanup(self):
        for n in self.daemons:
            n.cleanup()
