set -xe

cargo build
sudo apt update
sudo apt install python3 python3-pip python3-venv libsqlite3-dev build-essential libtool autotools-dev automake pkg-config bsdmainutils python3 libevent-dev libboost-system-dev libboost-filesystem-dev libboost-test-dev libboost-thread-dev

# FIXME: dl it from bitcoincore.org post branch-off
git clone https://github.com/bitcoin/bitcoin && cd bitcoin
git checkout v0.21.0rc1
./contrib/install_db4.sh `pwd`
./autogen.sh
export BDB_PREFIX="`pwd`/db4"
./configure BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" BDB_CFLAGS="-I${BDB_PREFIX}/include" --without-gui --disable-tests --disable-bench --enable-c++17
make -j4 && sudo make install
cd ..

python3 -m venv venv
. venv/bin/activate
pip install -r tests/requirements.txt
TEST_DEBUG=1 pytest -vvv -n2 tests/
