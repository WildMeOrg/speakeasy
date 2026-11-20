# Build context is the repository root:
#   docker build -f deploy/Dockerfile -t speakeasy .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=build /src/target/release/speakeasy /usr/local/bin/speakeasy
USER nobody
EXPOSE 8787
ENTRYPOINT ["speakeasy", "relay", "--listen", "0.0.0.0:8787"]
