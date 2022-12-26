"""
Lot of the code here is stolen from C-lightning's test suite. This is surely
Rusty Russell or Christian Decker who wrote most of this (I'd put some sats on
cdecker), so credits to them ! (MIT licensed)
"""
import bip32
import coincurve
import itertools
import json
import logging
import os
import platform
import re
import socket
import subprocess
import threading
import time

from bip380.descriptors import Descriptor
from bip380.miniscript import SatisfactionMaterial
from test_framework import serializations
from typing import Optional


TEST_PROFILING = bool(int(os.getenv("TEST_PROFILING", "0")))
TIMEOUT = int(os.getenv("TIMEOUT", 60))
TEST_DEBUG = os.getenv("TEST_DEBUG", "0") == "1"
EXECUTOR_WORKERS = int(os.getenv("EXECUTOR_WORKERS", 20))
POSTGRES_USER = os.getenv("POSTGRES_USER", "")
POSTGRES_PASS = os.getenv("POSTGRES_PASS", "")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_IS_SETUP = POSTGRES_USER and POSTGRES_PASS and POSTGRES_HOST
VERBOSE = os.getenv("VERBOSE", "0") == "1"
LOG_LEVEL = os.getenv("LOG_LEVEL", "debug")
assert LOG_LEVEL in ["trace", "debug", "info", "warn", "error"]
DEFAULT_REV_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "target/debug/revaultd"
)
REVAULTD_PATH = os.getenv("REVAULTD_PATH", DEFAULT_REV_PATH)
DEFAULT_MIRADORD_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "servers",
    "miradord",
    "target",
    "debug",
    "miradord",
)
MIRADORD_PATH = os.getenv("MIRADORD_PATH", DEFAULT_MIRADORD_PATH)
DEFAULT_COORD_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "servers",
    "coordinatord",
    "target",
    "debug",
    "coordinatord",
)
COORDINATORD_PATH = os.getenv("COORDINATORD_PATH", DEFAULT_COORD_PATH)
DEFAULT_COSIG_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "servers",
    "cosignerd",
    "target/debug/cosignerd",
)
COSIGNERD_PATH = os.getenv("COSIGNERD_PATH", DEFAULT_COSIG_PATH)
DEFAULT_BITCOIND_PATH = "bitcoind"
BITCOIND_PATH = os.getenv("BITCOIND_PATH", DEFAULT_BITCOIND_PATH)
WT_PLUGINS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wtplugins")


COIN = 10**8


def wait_for(success, timeout=TIMEOUT, debug_fn=None):
    """
    Run success() either until it returns True, or until the timeout is reached.
    debug_fn is logged at each call to success, it can be useful for debugging
    when tests fail.
    """
    start_time = time.time()
    interval = 0.25
    while not success() and time.time() < start_time + timeout:
        if debug_fn is not None:
            logging.info(debug_fn())
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


class Participant:
    def __init__(self):
        self.hd = bip32.BIP32.from_seed(os.urandom(32), network="test")


class User(Participant):
    def __init__(self):
        super(User, self).__init__()

    def get_xpub(self):
        return self.hd.get_xpub()

    def sign_revocation_psbt(self, psbt_str, deriv_index, acp=False):
        """Attach an ALL signature to the PSBT with the key at {deriv_index}"""
        assert isinstance(psbt_str, str)

        psbt = serializations.PSBT()
        psbt.deserialize(psbt_str)
        assert len(psbt.inputs) == 1, "Invalid revocation PSBT"
        assert (
            serializations.make_p2wsh(psbt.inputs[0].witness_script)
            == psbt.inputs[0].witness_utxo.scriptPubKey
        )

        script_code = psbt.inputs[0].witness_script
        sighash = serializations.sighash_all_witness(script_code, psbt, 0, acp)
        privkey = coincurve.PrivateKey(self.hd.get_privkey_from_path([deriv_index]))
        sighash_byte = b"\x01" if not acp else b"\x81"
        sig = privkey.sign(sighash, hasher=None) + sighash_byte

        pubkey = self.hd.get_pubkey_from_path([deriv_index])
        psbt.inputs[0].partial_sigs[pubkey] = sig

        return psbt.serialize()

    def sign_unvault_psbt(self, psbt_str, deriv_index):
        """Attach an ALL signature to the PSBT with the key at {deriv_index}"""
        assert isinstance(psbt_str, str)

        psbt = serializations.PSBT()
        psbt.deserialize(psbt_str)
        assert len(psbt.inputs) == 1, "Invalid Unvault PSBT"
        assert (
            serializations.make_p2wsh(psbt.inputs[0].witness_script)
            == psbt.inputs[0].witness_utxo.scriptPubKey
        )

        script_code = psbt.inputs[0].witness_script
        sighash = serializations.sighash_all_witness(script_code, psbt, 0)
        privkey = coincurve.PrivateKey(self.hd.get_privkey_from_path([deriv_index]))
        sig = privkey.sign(sighash, hasher=None) + b"\x01"  # ALL

        pubkey = self.hd.get_pubkey_from_path([deriv_index])
        psbt.inputs[0].partial_sigs[pubkey] = sig

        return psbt.serialize()

    def sign_spend_psbt(self, psbt_str, deriv_indexes):
        """Attach an ALL signature to each PSBT input with the keys at
        {deriv_indexes}"""
        assert isinstance(psbt_str, str)
        assert isinstance(deriv_indexes, list)

        psbt = serializations.PSBT()
        psbt.deserialize(psbt_str)
        assert len(psbt.inputs) == len(deriv_indexes), "Not enough derivation indexes"

        for (i, psbtin) in enumerate(psbt.inputs):
            script_code = psbtin.witness_script
            sighash = serializations.sighash_all_witness(script_code, psbt, i)
            privkey = coincurve.PrivateKey(
                self.hd.get_privkey_from_path([deriv_indexes[i]])
            )
            sig = privkey.sign(sighash, hasher=None) + b"\x01"  # ALL

            pubkey = self.hd.get_pubkey_from_path([deriv_indexes[i]])
            psbtin.partial_sigs[pubkey] = sig

        return psbt.serialize()


class Cosig(Participant):
    def __init__(self):
        super(Cosig, self).__init__()
        self.static_key_path = "m/0"

    def get_static_key(self):
        return self.hd.get_pubkey_from_path(self.static_key_path)

    def get_bitcoin_priv(self):
        return self.hd.get_privkey_from_path(self.static_key_path)


def get_participants(n_stk, n_man, n_stkman=0, with_cosigs=True):
    """Get the configuration entries for each participant."""
    stakeholders = [User() for _ in range(n_stk)]
    cosigs = [Cosig() for _ in range(n_stk)] if with_cosigs else []
    managers = [User() for _ in range(n_man)]

    stkman_stk = [User() for _ in range(n_stkman)]
    stkman_cosig = [Cosig() for _ in range(n_stkman)] if with_cosigs else []
    stkman_man = [User() for _ in range(n_stkman)]

    return (
        stakeholders,
        cosigs,
        managers,
        stkman_stk,
        stkman_cosig,
        stkman_man,
    )


def get_descriptors(stks_xpubs, cosigs_keys, mans_xpubs, mans_thresh, cpfp_xpubs, csv):
    # tests/test_framework/../../contrib/tools/mscompiler/target/debug/mscompiler
    mscompiler_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "contrib",
            "tools",
            "mscompiler",
        )
    )
    cwd = os.getcwd()
    os.chdir(mscompiler_dir)
    try:
        subprocess.check_call(["cargo", "build"])
    except subprocess.CalledProcessError as e:
        logging.error(f"Error compiling mscompiler: {str(e)}")
        raise e
    finally:
        os.chdir(cwd)

    mscompiler_bin = os.path.join(mscompiler_dir, "target", "debug", "mscompiler")
    cmd = [
        mscompiler_bin,
        f"{json.dumps(stks_xpubs)}",
        f"{json.dumps(cosigs_keys)}",
        f"{json.dumps(mans_xpubs)}",
        str(mans_thresh),
        f"{json.dumps(cpfp_xpubs)}",
        str(csv),
    ]
    try:
        descs_json = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running mscompiler with command '{' '.join(cmd)}'")
        raise e

    descs = json.loads(descs_json)
    return (
        Descriptor.from_str(descs["deposit_descriptor"]),
        Descriptor.from_str(descs["unvault_descriptor"]),
        Descriptor.from_str(descs["cpfp_descriptor"]),
    )


def finalize_input(descriptor, psbtin, derivation_index, max_sequence=2**32):
    """Produce a valid witness for this PSBT input, given its descriptor.

    The PSBT must have all signatures, it will raise otherwise.
    """
    desc = Descriptor.from_str(str(descriptor))
    desc.derive(derivation_index)

    sat_material = SatisfactionMaterial(
        signatures=psbtin.partial_sigs, max_sequence=max_sequence
    )
    stack = desc.satisfy(sat_material)

    assert stack is not None
    psbtin.final_script_witness = serializations.CTxInWitness(
        serializations.CScriptWitness(stack)
    )


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

            if e.args[0] == "AF_UNIX path too long" and os.uname()[0] == "Linux":
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
    def __init__(self, socket_path, config_file, logger=logging):
        self.socket_path = socket_path
        self.logger = logger
        self.next_id = 0
        self.config_file = config_file

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
                try:
                    return json.loads(buff)
                except json.JSONDecodeError:
                    # There is more to read, continue
                    # FIXME: this is a workaround for large reads, but we could
                    # eventually introduce an "end" marker in revaultd's responses,
                    # such as '\n'.
                    continue

    def __getattr__(self, name):
        """Intercept any call that is not explicitly defined and call @call.

        We might still want to define the actual methods in the subclasses for
        documentation purposes.
        """
        name = name.replace("_", "-")

        def wrapper(*args, **kwargs):
            if len(args) != 0 and len(kwargs) != 0:
                raise RpcError(
                    name, {}, "Cannot mix positional and non-positional arguments"
                )
            elif len(args) != 0:
                return self.call(name, payload=args)
            else:
                return self.call(name, payload=list(kwargs.values()))

        return wrapper

    # FIXME: support named parameters on the Rust server!
    def call(self, method, payload=[]):
        self.logger.debug("Calling %s with payload %r", method, payload)

        if platform.system() == "Windows":
            bin = os.path.join(
                os.path.dirname(__file__), "..", "..", "target", "debug", "revault-cli"
            )
            cmd_line = [bin, "--conf", self.config_file, method, *payload]
            resp = subprocess.check_output(
                cmd_line,
                shell=True,
                universal_newlines=True,
                text=True,
                encoding="utf-8",
            )
            resp = json.loads(resp)
            self.logger.debug(f"Received response for {method} call: {resp}")

        else:
            # FIXME: we open a new socket for every readobj call...
            sock = UnixSocket(self.socket_path)
            msg = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": method,
                    "params": payload,
                }
            )
            sock.sock.send(msg.encode())
            this_id = self.next_id
            resp = self._readobj(sock)

            self.logger.debug("Received response for %s call: %r", method, resp)
            if "id" in resp and resp["id"] != this_id:
                raise ValueError(
                    "Malformed response, id is not {}: {}.".format(this_id, resp)
                )
            sock.close()

        if not isinstance(resp, dict):
            raise ValueError(
                "Malformed response, response is not a dictionary %s." % resp
            )
        elif "error" in resp:
            raise RpcError(method, payload, resp["error"])
        elif "result" not in resp:
            raise ValueError('Malformed response, "result" missing.')
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
        """Start the underlying process and start monitoring it."""
        logging.debug("Starting '%s'", " ".join(self.cmd_line))
        self.proc = subprocess.Popen(
            self.cmd_line,
            stdin=stdin,
            stdout=stdout if stdout else subprocess.PIPE,
            stderr=stderr if stderr else subprocess.PIPE,
            env=self.env,
        )
        self.thread = threading.Thread(target=self.tail)
        self.thread.daemon = True
        self.thread.start()
        self.running = True

    def save_log(self):
        if self.outputDir:
            logpath = os.path.join(self.outputDir, "log")
            with open(logpath, "w") as f:
                for l in self.logs:
                    f.write(l + "\n")

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
        out = self.proc.stdout.readline
        err = self.proc.stderr.readline
        for line in itertools.chain(iter(out, ""), iter(err, "")):
            if len(line) == 0:
                break
            if self.log_filter(line.decode("utf-8")):
                continue
            if self.verbose:
                logging.debug(f"{self.prefix}: {line.decode().rstrip()}")
            with self.logs_cond:
                self.logs.append(str(line.rstrip()))
                self.logs_cond.notifyAll()
        self.running = False
        self.proc.stdout.close()
        self.proc.stderr.close()

    def is_in_log(self, regex, start=0):
        """Look for `regex` in the logs."""

        ex = re.compile(regex)
        for l in self.logs[start:]:
            if ex.search(l):
                logging.debug("Found '%s' in logs", regex)
                return l

        logging.debug(f"{self.prefix} : Did not find {regex} in logs")
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

            with self.logs_cond:
                if pos >= len(self.logs):
                    if not self.running:
                        raise ValueError("Process died while waiting for logs")
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
