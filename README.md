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

The project is still at a pretty early stage but if you want to start playing around with
`revaultd` you can use the `regtest_manager` script (that we use for hand testing) and
the sample configuration from `contrib/`:
```
$ . contrib/regtest_manager
$ start_regtest
$ fund_regtest
$ start_revaultd
$ re listvaults
{"id":"revault-cli-92537","jsonrpc":"2.0","result":{"vaults":[{"address":"bcrt1q0ty30ss87wlsvsgvrxsg62ql8yqlu0dv3tsu4gsl772xmvsrw39qlutjsf","amount":1000000000,"derivation_index":0,"status":"unconfirmed","txid":"12843e238f59a7ffd5f0a2a28a65cd20781aa05161cfd53a3d7f56285e61b90e","updated_at":1614209188,"vout":1}]}}
$ re getrevocationtxs 12843e238f59a7ffd5f0a2a28a65cd20781aa05161cfd53a3d7f56285e61b90e:1
{"id":"revault-cli-92891","jsonrpc":"2.0","result":{"cancel_tx":"cHNidP8BAF4CAAAAAc4RMyzSOoRpg+HR+bicF7GpKjOI2tonstEVtatRgC9SAAAAAAASAAAAAcramTsAAAAAIgAgeskXwgfzvwZBDBmgjSgfOQH+PayK4cqiH/eUbbIDdEoAAAAAAAEBK7Q9mjsAAAAAIgAgkZsLTmCBE0UTOapo8tzU97jFVv+fHh4Y+Y1SkBfMMG4BAwSBAAAAAQX9RwFSIQOEoGzvh3EFsazZvA6Qb609TIK4OkXuuPz2Eo3YKk+5xSED+lw1lkwnnrMBljpOnJyczV2en7v3QZee+1t/9PAABz5SrmR2qRSDL7y+QT7pBs+sxl0GpJlQM5BtbIisa3apFKrKneB67gEXVykGpeXyzLdGHA1UiKxsk2t2qRTh3bX059mGMhlF0I4ObpMO9VamgIisbJNrdqkUVbeuDJdRpOq7YfvN73KUhtVg8PaIrGyTVIdnVCECZEz54reP6wp1HlBQL1MKTL0LvaMCB3lgU5HnFlTdZsIhA87VXRIIvYxrQrEeKbqld3EcroMbOhKWYHxeXT7TZfScIQJiN/ZV879F/Wt6oA6RwmA9YVXxzAAeQPXkdmLZZcTHeSEDCjy8+/33Ei/n+oMDVMlW6mWV8tveIyhvA7wewMFoXKNUrwESsmgAAQGLVCECJjTDyAAanncAkFKBrmAd1zpDdeDngBwi/8wEQ/VZmTUhA4FIpqAnHmYXb71pszO9ltWB2t/K8UExfgP3Ve+um0LtIQMyE0zmB3quwrU2I3kUumH5TcoKddk2B+EwbBssrRKbHSECvVazU4We3rz6KYFmaVOILackL+7bXzjcToJ6miTuKM5UrgA=","emergency_tx":"cHNidP8BAF4CAAAAAQ65YV4oVn89OtXPYVGgGnggzWWKoqLw1f+nWY8jPoQSAQAAAAD9////AQyEmjsAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBKwDKmjsAAAAAIgAgeskXwgfzvwZBDBmgjSgfOQH+PayK4cqiH/eUbbIDdEoBAwSBAAAAAQWLVCECJjTDyAAanncAkFKBrmAd1zpDdeDngBwi/8wEQ/VZmTUhA4FIpqAnHmYXb71pszO9ltWB2t/K8UExfgP3Ve+um0LtIQMyE0zmB3quwrU2I3kUumH5TcoKddk2B+EwbBssrRKbHSECvVazU4We3rz6KYFmaVOILackL+7bXzjcToJ6miTuKM5UrgAA","emergency_unvault_tx":"cHNidP8BAF4CAAAAAc4RMyzSOoRpg+HR+bicF7GpKjOI2tonstEVtatRgC9SAAAAAAASAAAAAcramTsAAAAAIgAgy7Co1PHzwoce0hHQR5RHMS72lSZudTF3bYrNgqLbkDYAAAAAAAEBK7Q9mjsAAAAAIgAgkZsLTmCBE0UTOapo8tzU97jFVv+fHh4Y+Y1SkBfMMG4BAwSBAAAAAQX9RwFSIQOEoGzvh3EFsazZvA6Qb609TIK4OkXuuPz2Eo3YKk+5xSED+lw1lkwnnrMBljpOnJyczV2en7v3QZee+1t/9PAABz5SrmR2qRSDL7y+QT7pBs+sxl0GpJlQM5BtbIisa3apFKrKneB67gEXVykGpeXyzLdGHA1UiKxsk2t2qRTh3bX059mGMhlF0I4ObpMO9VamgIisbJNrdqkUVbeuDJdRpOq7YfvN73KUhtVg8PaIrGyTVIdnVCECZEz54reP6wp1HlBQL1MKTL0LvaMCB3lgU5HnFlTdZsIhA87VXRIIvYxrQrEeKbqld3EcroMbOhKWYHxeXT7TZfScIQJiN/ZV879F/Wt6oA6RwmA9YVXxzAAeQPXkdmLZZcTHeSEDCjy8+/33Ei/n+oMDVMlW6mWV8tveIyhvA7wewMFoXKNUrwESsmgAAA=="}}
$ re stop
```
You can find more RPC commands at [`doc/API.md`](doc/API.md) but all aren't implemented
yet!

See also the [functional tests](tests/) for a more complete integration (especially with
the coordinator).

# Contributing

Contributions are very welcome. For general guidelines, see [CONTRIBUTING.md](doc/CONTRIBUTING.md).


# Licence

Released under the BSD 3-Clause Licence. See the [LICENCE](LICENCE) file.
