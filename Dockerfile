# syntax=docker/dockerfile:1.7
FROM rust:1.96.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p contextosd

# Distroless, non-root, no shell.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/contextosd /usr/local/bin/contextosd
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/contextosd", "--config", "/etc/contextos/contextosd.toml"]
