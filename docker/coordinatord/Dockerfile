FROM rust:latest as builder

RUN git clone https://github.com/revault/coordinatord \
&& cd coordinatord \
&& cargo install --path .

EXPOSE 8383

COPY "entrypoint.sh" .
COPY "config.toml" .

RUN /bin/sh -c "chmod +x entrypoint.sh"

