"""
Most of the code here is stolen from C-lightning's test suite. This is surely
Rusty Russell or Christian Decker who wrote most of this (I'd put some sats on
cdecker), so credits to them ! (MIT licensed)
"""
from bitcoin.rpc import RawProxy as BitcoinProxy
from bitcoin.wallet import CKey
from decimal import Decimal
from ephemeral_port_reserve import reserve

import bitcoin
import logging
import os
import re
import subprocess
import threading
import time


TIMEOUT = int(os.getenv("TIMEOUT", 100))


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


def write_config(filename, opts=None, network='regtest'):
    with open(filename, 'w') as f:
        f.write(f"chain={network}\n")
        f.write(f"[{network}]\n")
        for k, v in opts.items():
            f.write(f"{k}={v}\n")


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

        # Should we be logging lines we read from stdout?
        self.verbose = verbose

        # A filter function that'll tell us whether to filter out the line (not
        # pass it to the log matcher and not print it to stdout).
        self.log_filter = lambda line: False

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
                logging.debug("%s: %s", self.prefix, line.decode().rstrip())
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
    def __init__(self, btc_conf_file, *args, **kwargs):
        self.__btc_conf_file__ = btc_conf_file

    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            # Python internal stuff
            raise AttributeError

        # Create a callable to do the actual call
        proxy = BitcoinProxy(btc_conf_file=self.__btc_conf_file__)

        def f(*args):
            return proxy._call(name, *args)

        # Make debuggers show <function bitcoin.rpc.name> rather than <function
        # bitcoin.rpc.<lambda>>
        f.__name__ = name
        return f


class BitcoinD(TailableProc):
    def __init__(self, bitcoin_dir="/tmp/bitcoind-test", rpcport=None):
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
            '-addresstype=bech32',
            '-rpcthreads=4',
        ]
        BITCOIND_REGTEST = {
            'port': self.p2pport,
            'rpcport': rpcport,
            'debug': 1,
            'fallbackfee': Decimal(1000) / bitcoin.core.COIN,
        }
        self.conf_file = os.path.join(bitcoin_dir, 'bitcoin.conf')
        write_config(self.conf_file, BITCOIND_REGTEST)
        self.rpc = SimpleBitcoinProxy(btc_conf_file=self.conf_file)
        self.proxies = []

        # So that it can locate the cookie file
        bitcoin.SelectParams("regtest")

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
        # As of 0.16, generate() is removed; use generatetoaddress.
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

    def pay_to(self, address, amount):
        self.generate_block(1)
        # So that we can boutique-compute fees in the tests by assuming we work
        # with 50 * 10**8 sats outputs.
        addr = self.getnewaddress()
        txid = self.rpc.sendtoaddress(addr, 50)
        self.generate_block(1, wait_for_mempool=str(txid))
        txin = self.rpc.listunspent(None, None, [addr], None, None)[-1]
        tx = self.rpc.createrawtransaction([
            {"txid": txin["txid"],
             "vout": txin["vout"],
             "amount": float(txin["amount"])}
        ], [
            {address: float(amount)}
        ])
        tx = self.rpc.signrawtransactionwithwallet(tx)["hex"]
        txid = self.rpc.sendrawtransaction(tx)
        self.generate_block(1, wait_for_mempool=str(txid))
        return txid

    def send_tx(self, hex_tx):
        txid = self.rpc.sendrawtransaction(hex_tx)
        self.generate_block(1, wait_for_mempool=str(txid))

    def has_utxo(self, address):
        """Test that we possess an utxo paying to this address."""
        if address in [utxo["address"] for utxo in self.rpc.listunspent()]:
            return True
        return False

    def startup(self):
        try:
            self.start()
        except Exception:
            self.stop()
            raise

        info = self.rpc.getnetworkinfo()

        if info['version'] < 160000:
            self.rpc.stop()
            raise ValueError("bitcoind is too old. At least version 16000"
                             " (v0.16.0) is needed, current version is {}"
                             .format(info['version']))

    def cleanup(self):
        try:
            self.stop()
        except Exception:
            self.proc.kill()
        self.proc.wait()
