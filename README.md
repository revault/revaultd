# revaultd

## About Revault

[Revault](https://github.com/revault/practical-revault/blob/master/revault.pdf) is a
Bitcoin vault architecture for multi-party situations.

Join `#revault` on freenode for discussing Revault development.

## About revaultd

`revaultd` is the core implementation of the `wallet` part from the [Revault protocol](https://github.com/revault/practical-revault).
Exposing an RPC interface, it aims to be actually used by participants with a GUI wrapper while
letting the possibility to access to the functionalities programmatically.

Both the "stakeholders" (participants who own the coin stored) and managers (participants who spend
the coins stored and may or may not own them) logic is part of this daemon.

## Hacking around

Please see [`doc/DEMO.md`](doc/DEMO.md) if you want a tutorial on how to do a deployment
in regtest on Linux of revaultd.
You can find more RPC commands at [`doc/API.md`](doc/API.md) but all aren't implemented
yet!

See also the [functional tests](tests/) for a more complete integration (especially with
the coordinator).

# Contributing

Contributions are very welcome. For general guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).


# Licence

Released under the BSD 3-Clause Licence. See the [LICENCE](LICENCE) file.
