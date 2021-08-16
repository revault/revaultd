# revaultd

## About Revault

[Revault](https://github.com/revault/practical-revault/blob/master/revault.pdf) is a
Bitcoin vault architecture for multi-party situations.

Join [`#revault` on Libera](https://web.libera.chat/?channels=#revault) for discussing Revault development.


## About revaultd

`revaultd` is the core implementation of the `wallet` part from the [Revault protocol](https://github.com/revault/practical-revault).
Exposing an RPC interface, it aims to be actually used by participants with a GUI wrapper while
letting the possibility to access to the functionalities programmatically.

The Bitcoin Script and transactions logic is contained in [`revault_tx`](https://github.com/revault/revault_tx/),
and the communication with the servers is in [`revault_net`](https://github.com/revault/revault_net).

The "stakeholders" (participants who don't actively take part in day-to-day fund managements
but pre-sign constrained spending authorizations) logic, "managers" (participants who use the pre-signed
authorizations to make payments) logic, and "stakeholders-managers" (participants wearing both hats) logic
are part of this daemon.

`revaultd` will connect to `bitcoind` via its RPC interface (version `0.21` minimum), the
[Coordinator](https://github.com/revault/coordinatord) and __*optionally*__ some [Cosigning Servers](https://github.com/revault/cosignerd)
if ran by a manager *in a deployment with Cosigning Servers*.

```
                            -----------                          -----------
                           |revault-gui|                  ----- | cosignerd |
                            \         /                 /        -----------
 --------------             ----------                 /         -----------
| coordinatord |  <------  | revaultd |  ------------- -------> | cosignerd |
 --------------             ----------                 \         -----------
                            /        \                  \        -----------
                           | bitcoind |                   ----- | cosignerd |
                            ----------                           -----------
```

You can find a reference of available RPC commands at [`doc/API.md`](doc/API.md).

Testing is performed both with Unit Tests directly integrated in the source (`cargo test`) and with a
[Python functional testing framework](tests/) permitting to test more complex scenarii in "blackbox"
(hitting only the RPC interface).

### Minimum Supported Rust Version

`revaultd` should always compile and pass tests using **Rust 1.43**.


## Hacking around

Checkout [The Aquarium](https://github.com/revault/aquarium) for a turnkey solution to try a Revault
deployment.

[`revault-gui`](https://github.com/revault/revault-gui) also has a tutorial on how to deploy Revault
"almost for real": on testnet between multiple participants.


# Contributing

Contributions are very welcome. For general guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).


# Licence

Released under the BSD 3-Clause Licence. See the [LICENCE](LICENCE) file.
