# syntax=docker/dockerfile:1
# Zceipt: API, dashboard and browser verifier in one image.
#   docker compose up            → http://127.0.0.1:8723 (keys printed in the log)
#   docker compose run --rm zceipt demo
FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS build
WORKDIR /src
COPY . .
# The cache mounts keep the registry, git checkouts and compiled dependencies between builds, so
# only the first build compiles everything.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p zceipt-cli && cp target/release/zceipt /zceipt

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10001 -m zceipt && mkdir /data && chown zceipt /data
COPY --from=build /zceipt /usr/local/bin/zceipt
USER zceipt
WORKDIR /data
EXPOSE 8723
ENTRYPOINT ["zceipt"]
CMD ["serve", "--listen", "0.0.0.0:8723", "--db", "/data/zceipt.db", "--verifier-url", "http://127.0.0.1:8723/verify/"]
