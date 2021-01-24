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

#### Without the servers

You can write and run tests that don't need the servers. By default, if no `POSTGRES_*`
environment variables are passed, the framework will skip the tests that depends on
servers:

```
# Adapt `-n`, `-v` and other environment variables to your needs
pytest -vvv -n4
```

#### With the servers

For spinning up the servers, the framework will need access to the binaries. Therefore you
must `init` the submodules (if you did not `clone` with `--recursive`) and compile the
servers code:
```
# From the root of the repository
cd tests/servers
git submodule update --init --recursive
cd coordinatord && cargo build
# TODO: add the other servers here when they are implemented
```

When you need a new version of the servers, you can update the submodules:
```
# From the root of the repository
cd tests/servers
git submodule update --remote --recursive
```

To run the server-requiring tests, pass the postgres credentials to the framework:
```
POSTGRES_USER="test" POSTGRES_PASS="test" TEST_DEBUG=1 pytest -vvv -n8
```
