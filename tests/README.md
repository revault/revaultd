## Revaultd blackbox tests

Here we test `revaultd` by starting it on a regression testing Bitcoin network,
and by then talking to it as an user would, from the outside.

Python scripts are used for the automation, and specifically the [`pytest` framework](https://docs.pytest.org/en/stable/index.html).

Credits: initially a lot of the fixtures and utilities were taken from the great
[C-lightning test framework](https://github.com/ElementsProject/lightning/tree/master/contrib/pyln-testing)
and adapted.

### Test dependencies

Functional tests dependencies can be installed like for any Python project.
```
# Create a new virtual environment, preferably.
python3 -m venv venv
. venv/bin/activate
# Get the deps
pip install -r tests/requirements.txt
```

### Test modes

Revault requires multiple servers and the version 0 of the protocol for deploying
it also specifies an additional coordination server. The wallet daemon, `revaultd`, will
therefore need to establish connections to those servers for some tests.

For these tests, the `RevaultNetwork` fixture will start multiple wallets (for the
stakeholders and the managers) as well as the required servers (coordinator, watchtowers
and cosigning servers). The code of these repositories is tracked as submodules in the
`tests/servers/` directory.

> Note: only the coordinator is implemented for now.

As the servers require a PostgreSQL backend, the functional testing framework will need
access to a running postgres instance. The credentials must be passed as environment
variables: `POSTGRES_USER`, `POSTGRES_PASS` and optionally `POSTGRES_HOST` (if not
`localhost`). The framework will take care of creating a database for each process
launched, and to drop it at teardown time.  

#### Compiling the servers

For spinning up the servers, the framework will need access to the binaries. Therefore you
must `init` the submodules (if you did not `clone` with `--recursive`) and compile the
servers code:
```
# From the root of the repository
git submodule update --init --recursive
cd tests/servers
cd cosignerd && cargo build && cd ..
cd miradord && cargo build && cd ..
```

When you need a new version of the servers, you can update the submodules. You can use a
script from `contrib/` that updates the servers and recompiles them:
```
# From the root of the repository
./contrib/recompile_tests_servers.sh
```

#### Using the real Coordinator

By default, the functional tests will use a dummy in-RAM coordinator (see
[`test_framework/coordinatord.py`](test_framework/coordinatord.py).

The tests can be ran using `coordinatord`, and some require its use.

In order to use it you'll first need to compile it:
```
# From the root of the repository
git submodule update --init --recursive
cd tests/servers/coordinatord && cargo build
cd ../../../
```

And then you'll need to set a Postgre backend up. The easiest way to do so is by using Docker:
```
docker run --rm -d -p 5432:5432 --name postgres-coordinatord -e POSTGRES_PASSWORD=revaultd_tests -e POSTGRES_USER=revaultd_tests -e POSTGRES_DB=coordinator_db postgres:alpine
```

To run the tests with, pass the postgres credentials to the framework:
```
# From the root of the repository
POSTGRES_USER=revaultd_tests POSTGRES_PASS=revaultd_tests pytest -vvv --ignore tests/servers -n 10
```


### Tips and tricks
#### Logging

We use the [Live Logging](https://docs.pytest.org/en/latest/logging.html#live-logs)
functionality from pytest. It is configured in (`pyproject.toml`)[../pyproject.toml] to
output `INFO`-level to the console. If a test fails, the entire `DEBUG` log is output.

You can override the config at runtime with the `--log-cli-level` option:
```
POSTGRES_USER=test POSTGRES_PASS=test pytest -vvv --log-cli-level=DEBUG -k test_getrevocationtxs
```

Note that we log each daemon log if `VERBOSE=1`, and we start them with `log_level = "debug"`.

#### Profiling

It can be very useful to profile a test or the test framework itself. To do so you can use the great
[`pytest-profiling`](https://github.com/man-group/pytest-plugins/tree/master/pytest-profiling)
plugin for pytest.
```
pip install pytest-profile
```

Run a test with `--profile` for it to create a `prof/` folder in the current working directory:
```
# For instance, of course adapt env vars to your own setup
cargo build --release && TEST_PROFILING=1 TEST_DIR=/mnt/tmp BITCOIND_PATH=$PWD/../tmp/bitcoind-22.0 REVAULTD_PATH=$PWD/target/release/revaultd POSTGRES_PASS=revault POSTGRES_USER=revault pytest -vvv --ignore tests/servers/ -k test_revault_network_securing --profile
```

The `--profile-svg` option is pretty handy for a quick summary:
```
# For instance, of course adapt env vars to your own setup
cargo build --release && TEST_PROFILING=1 TEST_DIR=/mnt/tmp BITCOIND_PATH=$PWD/../tmp/bitcoind-22.0 REVAULTD_PATH=$PWD/target/release/revaultd POSTGRES_PASS=revault POSTGRES_USER=revault pytest -vvv --ignore tests/servers/ -k test_revault_network_securing --profile --profile-svg
```

[`snakeviz`](https://github.com/jiffyclub/snakeviz) is another way of visualizing the profile
information:
```
pip install snakeviz
# For instance
snakeviz prof/test_large_spends.prof
```

A test module is present containing small tests to profile the test framework at
`tests/test_profiling.py`.

For more about profiling in Python generally, see [the
doc](https://docs.python.org/3/library/profile.html).

### Test lints

Just use [`black`](https://github.com/psf/black).
