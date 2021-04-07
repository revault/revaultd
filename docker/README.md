# Use Revault with docker.

# Prerequisites

* `docker`
* `docker-compose`

`docker pull rust:latest`

# Run [coordinatord](https://github.com/revault/coordinatord)

Add the participants noise keys to the `coordinatord/config.toml`.

```
docker-compose run coordinatord
```

It creates a volume `${PWD}/coordinatord_volume` which stores the
postgres db and the coordinatord datadir.
