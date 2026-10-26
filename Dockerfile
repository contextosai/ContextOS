# syntax=docker/dockerfile:1.7
FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY . .
# Use the image's installed compiler without installing development components.
RUN grep -Fxq "channel = \"$RUST_VERSION\"" rust-toolchain.toml \
    && RUSTUP_AUTO_INSTALL=0 cargo "+$RUST_VERSION" build --release --locked \
        -p contextosd -p towerd

# The Tower UI: static files, served by towerd when [tower] dir points at them.
FROM node:26.12.1-bookworm-slim AS console
WORKDIR /src/tower
COPY tower/package.json tower/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tower/ ./
RUN npm run build

# Distroless, non-root, no shell.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/contextosd /usr/local/bin/contextosd
# The governance plane: run the same image with --entrypoint /usr/local/bin/towerd.
COPY --from=build /src/target/release/towerd /usr/local/bin/towerd
COPY --from=console /src/tower/dist /usr/share/contextos/tower
COPY LICENSE LICENSE-docs NOTICE TRADEMARKS.md THIRD_PARTY_NOTICES.txt /usr/share/licenses/contextos/
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/contextosd", "--config", "/etc/contextos/contextosd.toml"]
