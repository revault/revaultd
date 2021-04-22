#!/usr/bin/env bash

if [ "$0" = "$BASH_SOURCE" ];then
	echo "You should source this script to benefit of aliases and functions."
	exit 0
fi

# Just spin up two nodes by default
n_nodes=2

start_regtest () {
	# Use the global env bitcoind by default
	if [ -z "$BITCOIND_PATH" ];then BITCOIND_PATH="/usr/local/bin/bitcoind";fi
	# They can set their root dir if they want to
	if [ -z "$PREFIX_DIR" ]; then PREFIX_DIR="$PWD/regtest";fi

	if [ "$#" == "1" ];then
		n_nodes=$1
	fi

	for i in $(seq $n_nodes);do
		bc_rpc=$((9000 + $i))
		bc_port=$((10000 + $i))
		bc_dir="$PREFIX_DIR/bcdir$i"

		mkdir -p "$bc_dir"
		cat <<EOF > $bc_dir/bitcoin.conf
regtest=1
[regtest]
connect=127.0.0.1:$(($bc_port - 1))
rpcport=$bc_rpc
bind=127.0.0.1:$bc_port
daemon=1
txindex=1
whitelist=127.0.0.1
fallbackfee=0.00001
debug=1
EOF

		eval "$BITCOIND_PATH -datadir=\"$bc_dir\""
		alias "bdreg$i"="$BITCOIND_PATH -datadir=\"$bc_dir\""
		echo "Started bitcoind #$i with P2P port $bc_port, RPC port $bc_rpc and datadir $bc_dir"

		bcli="bitcoin-cli -regtest -datadir=$bc_dir -rpcwallet=\"test\""
		while [ $($bcli getblockchaininfo &> /dev/null; echo $?) -ne 0 ];do
			echo "Waiting for bitcoind to warmup.."
			sleep 0.5
		done
		if [ $($bcli -named createwallet wallet_name="test" descriptors=true load_on_startup=true &> /dev/null; echo $?) -eq 0 ];then
			echo "Created descriptor wallet 'test'";
		fi
		alias "bcreg$i"="$bcli"
		echo ""
	done

	echo ""
	echo "Started $n_nodes bitcoind daemons."
}

# Generates blocks not too quickly and keep everyone in sync, until we die
generate_regtest () {
	while true;do
		for i in $(seq $n_nodes);do
			bc_dir="$PREFIX_DIR/bcdir$i"
			bcli="bitcoin-cli -regtest -datadir=$bc_dir -rpcwallet=\"test\""
			if [ $($bcli generatetoaddress 1 $($bcli getnewaddress 2> /dev/null) &> /dev/null; echo $?) -ne 0 ];then
				return
			fi
			sleep 3
		done
		sleep 15
	done
}

# First param is CLI, second is the number of blocks to wait for
wait_for_blocks () {
	desired_height=$(($($1 getbestblockhash) + $2));
	while test $($1 getbestblockhash) -lt $desired_height;do
		sleep 1
	done
}

fund_regtest () {
	if [ $(jq --help > /dev/null; echo $?) -ne 0 ];then
		echo "I need the 'jq' utility in order to fund channels."
		return
	fi

	# We cannot brutally generate blocks here or we'll fork
	# FIXME: Or maybe if there is only one generator this would be ok ?
	echo "Getting some bitcoins on each bitcoin daemon"
	# Use the first node as the block generator
	bc_dir="$PREFIX_DIR/bcdir1"
	miner="bitcoin-cli -regtest -datadir=$bc_dir -rpcwallet=test"
	for n in $(seq 110);do
		if [ "$n" = "1" ];then
			while [ $($miner getblockchaininfo > /dev/null; echo $?) -ne 0 ];do
				echo "Waiting for bitcoind to warmup.."
				sleep 1
			done
		fi
		for i in $(seq $n_nodes);do
			bc_dir="$PREFIX_DIR/bcdir$i"
			bcli="bitcoin-cli -regtest -datadir=$bc_dir -rpcwallet=test"
			$miner generatetoaddress 1 $($bcli getnewaddress 2>/dev/null) > /dev/null
			sleep 0.001
		done
		echo -en "\r$n/110 blocks generated"
	done
	echo ""
	echo "Waiting for all nodes to agree about the tip"
	tip=$($miner getbestblockhash)
	for node in $(seq $n_nodes);do
		bc_dir="$PREFIX_DIR/bcdir$i"
		bcli="bitcoin-cli -regtest -datadir=$bc_dir -rpcwallet=\"test\""
		our_tip=$($bcli getbestblockhash)
		while test "$our_tip" != "$tip"; do sleep 0.05;done
	done
	echo ""

	echo "(We start generating blocks in background)..."
	generate_regtest &

	echo "Ok, you should be all set!"
}

# Stop the regression testing network
stop_regtest () {
	PREFIX_DIR="$PWD/regtest"

	if ! test -d "$PREFIX_DIR";then
		echo "No regtest/ directory here..."
		return
	fi

	for i in $(seq $n_nodes);do
		pid=$(cat "$PREFIX_DIR/bcdir$i/regtest/bitcoind.pid")
		bc_dir="$PREFIX_DIR/bcdir$i"
		bitcoin-cli -datadir="$bc_dir" stop
		wait -fn $pid &>/dev/null
		echo "bitcoind #$i stopped"
	done
}

# Start a single revault wallet daemon
start_revaultd () {
    # FIXME: write the config to the PREFIX_DIR ourselves..
    if [ -z "$REVAULTD_CONFIG_PATH" ];then REVAULTD_CONFIG_PATH="./config_regtest.toml";fi
    cargo run --bin revaultd -- --conf "$REVAULTD_CONFIG_PATH";
    alias re="cargo run --bin revault-cli -- --conf $REVAULTD_CONFIG_PATH";
}

# Fund a new vault, optionally takes an amount
fund_vault () {
    if [ -z "$REVAULTD_CONFIG_PATH" ];then REVAULTD_CONFIG_PATH="./config_regtest.toml";fi
    amount=10;
    if [ "$#" == "1" ];then
        amount=$1;
    fi

    addr=$(cargo run --bin revault-cli -- --conf "$REVAULTD_CONFIG_PATH" getdepositaddress|jq -r .result.address);
    bc_dir="$PREFIX_DIR/bcdir1";
    miner="bitcoin-cli -regtest -datadir=$bc_dir -rpcwallet=test";
    $miner sendtoaddress $addr $amount;
    sleep 0.5;
    $miner generatetoaddress 6 $($bcli getnewaddress 2> /dev/null) &> /dev/null;
}

# Deletes the root parent of all datadirs
delete_regtest () {
	PREFIX_DIR="$PWD/regtest"

	if ! test -d "$PREFIX_DIR";then
		echo "No regtest/ directory here..."
		return
	fi

	rm -r "$PREFIX_DIR"
}
