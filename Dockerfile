# syntax=docker/dockerfile:1
# Receipts: API, dashboard and browser verifier in one image.
#   docker compose up            → http://127.0.0.1:8723 (keys printed in the log)
#   docker compose run --rm receipts demo
FROM rust:1.95-bookworm AS build
WORKDIR /src
COPY . .
# The cache mounts keep the registry, git checkouts and compiled dependencies between builds, so
# only the first build compiles everything.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p receipts-cli && cp target/release/receipts /receipts

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10001 -m receipts && mkdir /data && chown receipts /data
COPY --from=build /receipts /usr/local/bin/receipts
USER receipts
WORKDIR /data
EXPOSE 8723
ENTRYPOINT ["receipts"]
CMD ["serve", "--listen", "0.0.0.0:8723", "--db", "/data/receipts.db", "--verifier-url", "http://127.0.0.1:8723/verify/"]
