# dezhan server image. Multi-stage: build the Ada/SPARK tree with a system
# GNAT (no Alire needed; every .gpr pins -gnat2022), then ship only the
# binaries on a distroless runtime so the image carries no shell or package
# manager. Builder and runtime share the Debian 12 glibc.
FROM debian:12-slim AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends gnat gprbuild ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build the three executables (server, cli, verifier) and every library.
# Link the GNAT Ada runtime statically (-largs -static): the distroless runtime
# has no libgnat/libgnarl shared objects, so a dynamically linked binary fails
# with "libgnarl-*.so: cannot open shared object file".
RUN gprbuild -p -P dezhan.gpr -cargs -O2 -largs -static

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=build /src/server/obj/dezhan_server   /usr/local/bin/dezhan_server
COPY --from=build /src/cli/obj/dezhan_cli         /usr/local/bin/dezhan_cli
COPY --from=build /src/verifier/obj/dezhan_verify /usr/local/bin/dezhan_verify

# Vault data lives on a mounted volume. distroless 'nonroot' is uid 65532.
VOLUME ["/data"]
EXPOSE 8080
USER nonroot

ENTRYPOINT ["/usr/local/bin/dezhan_server"]
CMD ["8080", "/data"]
