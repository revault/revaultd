# Tutorial: using revaultd for the first time!

This tutorial is going to outline how to deploy a **demo** of Revault. We'll do everything on one computer, and we'll use regtest. Please note that this tutorial is **not** suitable for mainnet, as further security precautions would be needed for real-world deployment.

This tutorial has been tested on Linux, it *might* work on Unix and it won't work for sure on Windows :)

## Prerequisites

### Understanding the Revault architecture
Please refer to [practical-revault](https://github.com/revault/practical-revault/) for in-depth explanation of the architecure.

Every stakeholder will need:
- `revaultd`
- `cosignerd`
- `revault-gui` (optional)

Every manager will need:
- `revaultd`
- `revault-gui` (optional)

Also, there must be **one** `coordinatord`

### Bitcoin Core version >= 0.21.0
See https://bitcoin.org/en/download

`revaultd` **won't work** with previous versions! Check your version with `bitcoind --version`

We'll use regtest: no need to have a synced node!

### Rust
`revaultd`, `cosignerd` and `coordinatord` are written in Rust. Since we don't publish compiled binaries (yet!), you'll need to have the Rust toolchain installed to be able to compile the projects.

Please refer to https://www.rust-lang.org/tools/install for instructions on how to install Rust.

Double check that your rust toolchain is **at least** 1.43.0:
```
cargo --version
```

(If you don't intend to use docker for the coordinator, you need **at least** Rust 1.46.0)

### Some text editor
There are various keys that you'll need to keep during the whole configuration. Obviously a text editor is not a good choice for storing real keys, but hey, we're in regtest. Open your favorite note-taking app (even Microsoft Word is fine, or even worse, Emacs)

### The Revault ceremony
`revaultd` supposes that you've already done a proper ceremony with all the stakeholders and managers, where you created the keys in a secure way and exchanged them.

If you're just exploring Revault you probably don't have time to do a proper ceremony: let's recreate something similar.

It's important to clarify how many managers and how many stakeholders you'll have: you must have at least 2 stakeholders and 1 manager. We'll have 2 stakeholders and 1 manager in this tutorial.

Revault supposes that every manager and every stakeholder has its own computer, but since we're just trying out things, we'll use a single computer in this tutorial. If you want to try out with multiple machines, please see the (below)[#Organizing the perfect Revault party] section.

Each entity in the company will have a pair of BIP32 keys: generating them is the first step in the ceremony. The ceremony is not fully specified yet, but it will instruct managers and stakeholders on how to securily create and store the keys. Since we're on regtest anyway, we don't really care much about security in this specific example: just create the keys on bip32.org or, if you don't know how to do it, just use the ones provided in the [example config](contrib/config_regtest.toml).

At this point your notes should contain:
```
stakeholder1: *xpriv* *xpub*
stakeholder2: *xpriv* *xpub*
manager1: *xpriv* *xpub*
```

### Docker (kinda optional)
We need docker to spin up the `coordinatord`'s Postgre database. You can avoid using docker though, and just spin up a Postgre database yourself.

### Python (kinda optional)
We use python to quickly generate a couple of Bitcoin keys. If you don't have Python on your computer it's fine, but you'll have to find a way to generate Bitcoin keys by yourself.

## Downloading the repositories
Let's start by creating a dedicated folder - this way if you don't like Revault it will be easier to erase everything :D
```
mkdir revault_tutorial
cd revault_tutorial
```
Download all the needed repositories: `cosignerd`, `coordinatord`, `revaultd`:
```
git clone -b 0.1 https://github.com/revault/coordinatord
git clone -b 0.1 https://github.com/revault/cosignerd
git clone -b 0.1 https://github.com/revault/revaultd
```

You working directory should look like:
```
.
├── coordinatord
├── cosignerd
├── revaultd
```

## Let's get started!
### 1. Spinning up Bitcoin Core
In this tutorial we'll use the regtest network. We'll use a custom data directory inside the `revault_tutorial`.
```
mkdir bitcoind_data
```

Start a Bitcoin Core node using
```
bitcoind -regtest -daemon -datadir=$PWD/bitcoind_data
```

### 2. Starting the coordinator
As we said, we need just one coordinator running, no matter how many stakeholders/managers there are.
We'll properly update the coordinator configuration later. For now, let's just retrieve the coordinator's noise key.
Cd into the coordinator:
```
cd coordinatord
```

Build the project:
```
cargo build
```

Coordinatord needs a Postgre database running, we'll spin it up using docker:
```
docker run --rm -d -p 5432:5432 --name postgres-coordinatord -e POSTGRES_PASSWORD=revault -e POSTGRES_USER=revault -e POSTGRES_DB=coordinator_db postgres:alpine
```

Now duplicate the config provided:
```
cp contrib/config.toml coordinatord_config.toml
```

and make sure that the `postgres_uri` is `postgresql://revault:revault@localhost:5432/coordinator_db`.

Don't bother with the noise keys now, we'll update them later.

Start the project:
```
cargo run -- --conf coordinatord_config.toml
```

Then please keep note of the noise key printed at startup, we'll need it later.

Now kill the coordinator with `CTRL-C`.

Go back to the parent directory for the next step
```
cd ../
```

Your notes should now look like:
```
stakeholder1: *xpriv* *xpub*
stakeholder2: *xpriv* *xpub*
manager1: *xpriv* *xpub*
coordinator: *noise key*
```

### 3. Configuring the cosigner
We'll need one cosigner for each stakeholder.
Cd into the cosignerd:
```
cd cosignerd
```

Let's start by compiling the project (it may take a while):
```
cargo build
```

#### Stakeholder 1
First of all, create a directory to store all the cosignerd data:
```
mkdir cosignerd_1_data
```

You can find an [example config](https://github.com/revault/cosignerd/tree/master/contrib/config.toml) to begin with. Copy it to `./cosigner_1_config.toml`
```
cp contrib/config.toml cosigner_1_config.toml
```

We'll need to modify it a bit:
- Don't bother with the noise keys now, we'll have to update them later.
- Update the data dir: we'll use `./cosignerd_1_data`
- Make sure the `listen` field is `127.0.0.1:20001`

The cosigner needs a bitcoin secret. Usually this is generated in a secure way during the ceremony, but for this tutorial we'll generate it using python3:
```
cd cosignerd_1_data
python3 -c 'import os;open("bitcoin_secret", "wb").write(bytes(1) + os.urandom(31))'
cd ..
```

Now start the project:
```
cargo run -- --conf cosigner_1_config.toml
```

It will print a Bitcoin public key and a Noise key. Save it in your notes, then kill `cosignerd` with `CTRL-C`.

#### Stakeholder 2
First of all, create a directory to store all the cosignerd data:
```
mkdir cosignerd_2_data
```

We'll copy the `cosigner_1_config.toml` and modify it a bit
```
cp cosigner_1_config.toml cosigner_2_config.toml
```

- Update the data dir: we'll use `./cosignerd_2_data`
- Update the `listen` field to `127.0.0.1:20002`

The cosigner needs a bitcoin secret. Usually this is generated in a secure way during the ceremony, but for this tutorial we'll generate it using python3:
```
cd cosignerd_2_data
python3 -c 'import os;open("bitcoin_secret", "wb").write(bytes(1) + os.urandom(31))'
cd ..
```

Now start the project:
```
cargo run -- --conf cosigner_2_config.toml
```

It will print a Bitcoin public key and a Noise key. Save it in your notes, then kill `cosignerd` with `CTRL-C`.

Your notes should now look like this:
```
stakeholder1: *xpriv* *xpub* *noise key*
stakeholder2: *xpriv* *xpub* *noise key*
manager1: *xpriv* *xpub* *noise key*
cosigner1: *bitcoin pubkey* *noise key*
cosigner2: *bitcoin pubkey* *noise key*
coordinator: *noise key*
```

Go back to the parent directory for the next step
```
cd ..
```
### 4. Creating the revaultd configuration
Cd into the project:
```
cd revaultd
```

Build it:
```
cargo build
```

Now we need to setup `revaultd` three times, one for each entity.

#### Stakeholder 1
Let's create a directory for storing revaultd data:
```
mkdir stake_1_data
```

`revaultd` needs a configuration file - you can find [here](../contrib/config_regtest.toml) an example of configuration.
The default path for the configuration is `~/.revault/revault.toml`, but for this example we'll use `./stake_1_config.toml`:
```
cp contrib/config_regtest.toml stake_1_config.toml
```

We'll need to modify the config a bit to fit our example:
- Update the `data_dir`: this is the directory where all the data will be saved. We'll use `./stake_1_data`. To avoid troubles if you want to try out the GUI, we'll insert this as an absolute path. Get the absolute path by typing:
```
echo $PWD/stake_1_data
```
and paste the result as the data dir.
- Update the `coordinator_host` with `127.0.0.1:8383`, `coordinator_noise_key` with the key obtained in step 2
- Update the `stakeholders_xpubs`: it will contain all the stakeholder xpubs created in the ceremony

```
stakeholders_xpubs = [
    *first stakeholder xpub*,
    *second stakeholder xpub*,
]
```
Please make sure that the keys are in the right order, the first as first and the second as second. Not doing so could lead to tricky bugs.
- Update the `managers_xpubs`: it will contain all the manager xpubs created in the ceremony:

```
managers_xpubs = [
    *first manager xpub*,
]
```

- Update the `cosigners_keys`: it will contain all the cosigner keys created in step 3

```
cosigners_keys = [
    *first cosigner key*,
    *second cosigner key*,
]
```
Please make sure that the keys are in the right order, the first as first and the second as second. Not doing so could lead to tricky bugs.

- Update the `stakeholder_config`: update `xpub` to match the first stakeholder's xpub; leave the watchtowers section as it is, it's not used (yet!)

- Remove the `manager_config`

- Update the `bitcoind_config` `addr` to the address of your bitcoin RPC. In regtest it defaults to `127.0.0.1:18443`. The one contained in the regtest config is the correct one if you're using the regtest manager script, as outlined below
- Update the `bitcoind_config` `cookie` file. Get the path of the cookie file by typing:
```
echo $PWD/../bitcoind_data/regtest/.cookie
```
and paste it into the configuration.

#### Stakeholder 2
Let's create a directory for storing revaultd data:
```
mkdir stake_2_data
```

We'll copy the first stakeholder config and modify it a bit:

```
cp stake_1_config.toml stake_2_config.toml
```

- Update the `data_dir`: this is the directory where all the data will be saved. We'll use `./stake_2_data`. To avoid troubles if you want to try out the GUI, we'll insert this as an absolute path. Get the absolute path by typing:
```
echo $PWD/stake_2_data
```
and paste the result as the data dir.

- Update the `stakeholder_config`: update `xpub` to match the second stakeholder's xpub; leave the watchtowers section as it is, it's not used (yet!)

#### Manager 1
Let's create a directory for storing revaultd data:
```
mkdir man_1_data
```

Again, copying the first stakeholder's configuration file
```
cp stake_1_config.toml man_1_config.toml
```

We'll need to modify the config a bit to fit our example:
- Update the `data_dir`: this is the directory where all the data will be saved. We'll use `./man_1_data`. To avoid troubles if you want to try out the GUI, we'll insert this as an absolute path. Get the absolute path by typing:
```
echo $PWD/man_1_data
```
and paste the result as the data dir.
- Delete the `stakeholder_config`
- Paste this `manager_config`:
```
[manager_config]
xpub = "xpub6Ap9B8sg9xsTLFyCG8BQadDEfk4mhoLtSBaVzG4691QKWGvLRrmgGT1zsHfDFqzHgSUcgQBr75ekSdyc6pf6vJPHTbG9HMvxWkg2mtdg69d"

[[manager_config.cosigners]]
host = "127.0.0.1:20001"
noise_key = "2b1df6c0618cf54955046ca5ca1dc113ddc1d63e89074b3efefae5847b1d7a63"

[[manager_config.cosigners]]
host = "127.0.0.1:20002"
noise_key = "f866b639cbd36fcf6c984bd70e1259aa4cad335c99a47ea3747d489f64d57e65"
```
- Update the `manager_config`: update `xpub` to match your first manager's xpub; the first cosigner key to match the first cosigner key obtained in step 3, the second cosigner key to match the second cosigner key obtained in step 3. Beware of the order of the keys! Swapping them could lead to nasty bugs.


### 5. Spinning up revaultd
Time to start revaultd! This will create the database and the watchonly wallet. After you run `revaultd` for the first time, the database and the watchonly wallet must be deleted if you wish to change one or more of the managers/stakeholders/cosigners keys.
To make things easier, we'll create a couple of aliases:
```
alias stake_1_d="cargo run --bin revaultd -- --conf stake_1_config.toml"
alias stake_1_cli="cargo run --bin revault-cli -- --conf stake_1_config.toml"
alias stake_2_d="cargo run --bin revaultd -- --conf stake_2_config.toml"
alias stake_2_cli="cargo run --bin revault-cli -- --conf stake_2_config.toml"
alias man_1_d="cargo run --bin revaultd -- --conf man_1_config.toml"
alias man_1_cli="cargo run --bin revault-cli -- --conf man_1_config.toml"
```

#### Stakeholder 1
Start the daemon:
```
stake_1_d
```

You'll see a line like:
```
[04-14][11:56:17][revaultd][INFO] Using Noise static public key: *a long key*
```
That's the noise key we need, save it, and stop the daemon:

```
stake_1_cli stop
```

If you get an error like:
```
Could not connect to *blabla*: 'Connection refused (os error 111)'
```
it means that `revaultd` died, and you may need to debug a bit ;( Inspect the logs in `stake_1_data/log`

#### Stakeholder 2
Start the daemon:
```
stake_2_d
```

You'll see a line like:
```
[04-14][11:56:17][revaultd][INFO] Using Noise static public key: *a long key*
```
That's the noise key we need, save it, and stop the daemon:

```
stake_2_cli stop
```

If you get an error like:
```
Could not connect to *blabla*: 'Connection refused (os error 111)'
```
it means that `revaultd` died, and you may need to debug a bit ;( Inspect the logs in `stake_2_data/log`

#### Manager 1
Start the daemon:
```
man_1_d
```

You'll see a line like:
```
[04-14][11:56:17][revaultd][INFO] Using Noise static public key: *a long key*
```
That's the noise key we need, save it, and stop the daemon:

```
man_1_cli stop
```

If you get an error like:
```
Could not connect to *blabla*: 'Connection refused (os error 111)'
```
it means that `revaultd` died, and you may need to debug a bit ;( Inspect the logs in `man_1_data/log`

Go back to the parent directory for the next step
```
cd ..
```

Your notes should now look like this:
```
stakeholder1: *xpriv* *xpub* *noise key*
stakeholder2: *xpriv* *xpub* *noise key*
manager1: *xpriv* *xpub* *noise key*
cosigner1: *bitcoin pubkey* *noise key*
cosigner2: *bitcoin pubkey* *noise key*
coordinator: *noise key*
```

### 6. Starting the cosigners

```
cd cosignerd
```

Update the configurations we created in step 2 (`cosigner_1_config` and `cosigner_2_config`):
- There has to be just one manager noise key, the one we just obtained. Delete the other `[[managers]]` section, we don't need it.
- The `daemon` field should be set to true

Now it's time to start the cosigners with the right config:
```
cargo run -- --conf cosigner_1_config.toml
cargo run -- --conf cosigner_2_config.toml
```

Go back to the parent directory for the next step
```
cd ..
```

### 7. Updating the coordinatord config

`coordinatord` needs all the Noise keys in its config.

```
cd coordinatord
```

Open the configuration file in `coordinatord_config.toml`, add all the manager noise keys and all the stakeholders noise keys. Leave the watchtowers keys empty, they're not used yet.
Also set `daemon=true`.

Your config file now should look like this (with your keys in it instead of those dummy keys, obviously):
```
daemon=true
data_dir = "./revault_coordinatord"
log_level = "debug"

postgres_uri = "postgresql://revault:revault@localhost:5432/coordinator_db"

managers = [
    "d2deeb8398f47789e1f5118c42834031e3722817a432192b74c363fdb36cc634",
]

stakeholders = [
    "eecd2a93f5b09b88519f38d620aa127333d1934987d18001132f07ffa3596c65",
    "614ad96890c309b8da6915ddb9eb1135caf228120178833e70798f20e0783b16",
]

watchtowers = []
```

Now start the `coordinatord` again:

```
cargo run -- --config coordinatord_config.toml
```

Go back to the parent directory for the next step
```
cd ../
```

### 8. Sending commands using the cli
Let's go back to the revaultd directory and start everything once again:
```
cd revaultd
stake_1_d
stake_2_d
man_1_d
```

Now, let's ask for info:

```
stake_1_cli getinfo
```

You should see something like:
```
{
  "result": {
    "blockheight": 0,
    "network": "regtest",
    "sync": 1.0,
    "vaults": 0,
    "version": "0.0.2"
  }
}
```

Do the same with `stake_2_cli` and `man_1_cli`, just to make sure everything works :)

### 9. Checking if you fucked up

Please run

```
stake_1_cli getdepositaddress
```

and then

```
stake_2_cli getdepositaddress
```

and then

```
man_1_cli getdepositaddress
```

If they all return the same address, cool, somehow you managed to not fuck it up. Otherwise, well, you fucked up.
Don't worrry, it happens. We're working towards making it happen less often by introducing descriptors in the configuration file, but in the meanwhile, you'll have to debug.

If the deposit address are different, it means that the descriptors created by `revaultd` are different. Please check that:

- The `stakeholders_xpubs` are all equal in all configurations, **the order of the keys MUST be the same**
- The `managers_xpubs` are all equal in all configurations, **the order of the keys MUST be the same**
- The `cosigners_keys` are all equal in all configurations, **the order of the keys MUST be the same**
- The `unvault_csv` is the same in every configuration

Delete your sqlite database and your watchonly wallet:

```
rm ./stake_1_data/revaultd.sqlite3
rm ./stake_2_data/revaultd.sqlite3
rm ./man_1_data/revaultd.sqlite3
rm -r ./stake_1_data/revaultd-watchonly-wallet-1/
rm -r ./stake_2_data/revaultd-watchonly-wallet-1/
rm -r ./man_1_data/revaultd-watchonly-wallet-1/
```

Restart `revaultd` and check again the deposit addresses. If that didn't work either, try restarting `bitcoind`, or open an issue, or ask on #revault on freenode :)

### 10. Playing around with the CLI

If you want to play around with the CLI a bit, all the available commands are listed in [doc/API.md][./API.md].

### 11. Wait, CLI only?!
Nah. We also have a GUI. Check out [revault-gui](https://github.com/revault/revault-gui) :)

## Organizing the perfect Revault party

Want to try out Revault on multiple computers? You can follow this tutorial, but please be mindful that:
1. You'll need to be on the same Bitcoin network - either one common regtest/signet, or testnet.
2. you'll need to reach the `cosignerd` and the `coordinatord` from outside `localhost`. You'll have to make sure to not bind on localhost (eg use `listen="0.0.0.0:<port>"` to listen on all interfaces)

## Testing
For testing you may find useful the [regtest manager script](../contrib/regtest_manager.sh). You will need to tweak the configuration we created in step 4 a bit, as the RPC address of the bitcoin node spawn by the script is `127.0.0.1:9001`.

This script only start regtest nodes and `revaultd`: you need to setup the whole infrastructure anyway, and start `cosignerd` and `coordinatord` by yourself.
```
$ . contrib/regtest_manager
$ start_regtest
$ fund_regtest
$ start_revaultd
$ fund_vault
$ re listvaults
{
  "result":{
    "vaults":[
      {
        "address":"bcrt1qkr46dkrymxpc2zgepz4cf7xcvpvl0h807rx2vcay6y5zy2ndkyyqkrc5ej",
        "amount":99938762,
        "blockheight":173,
        "derivation_index":0,
        "received_at":1617789169,
        "status":"canceling",
        "txid":"b594aef28c812177dcd41373b7d52c776c60df992821ca6007943b53cb47fb3d",
        "updated_at":1618474779,
        "vout":0
      }
    ]
  }
}
$ re getrevocationtxs b594aef28c812177dcd41373b7d52c776c60df992821ca6007943b53cb47fb3d:0
{
  "result":{
    "cancel_tx":"*a long PSBT*",
    "emergency_tx":"*another long PSBT*",
    "emergency_unvault_tx":"*another long PSBT*"
  }
}
$ re stop
```
