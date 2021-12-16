# See https://gitlab.com/sequoia-pgp/sequoia/-/blob/main/README.md#debian
# for system requirements
FROM debian:bookworm AS build

# create a sandbox user for the build (in ~builder) and install (in /opt)
# give it permissions to the build dir and home
# upgrade everything
# add dependencies, as specified by the Sequoia README.md file
RUN groupadd builder && \
    useradd --no-log-init --create-home --gid builder builder && \
    apt-get update && \
    apt-get upgrade --assume-yes && \
    apt-get install --assume-yes --no-install-recommends \
        ca-certificates \
        capnproto \
        cargo \
        git \
        libclang-dev \
        libsqlite3-dev \
        libssl-dev \
        make \
        nettle-dev \
        pkg-config \
        python3-dev \
        python3-setuptools \
        python3-cffi \
        python3-pytest \
        rustc \
        && \
    apt-get clean && \
    chown builder /opt

COPY --chown=builder:builder . /home/builder/sequoia

# switch to the sandbox user
USER builder

# retry build because cargo sometimes segfaults during download (#918854)
#
# the `build-release` target is used instead of the default because
# `install` calls it after anyways
RUN cd /home/builder/sequoia && \
    CARGO_TARGET_DIR=target cargo build -p sequoia-sq --release && \
    install --strip -D --target-directory /opt/usr/local/bin \
                  target/release/sq

FROM debian:bookworm-slim AS sq-base

RUN groupadd user && \
    useradd --no-log-init -g user user && \
    mkdir /home/user && \
    chown -R user:user /home/user && \
    apt-get update && \
    apt-get upgrade --assume-yes && \
    apt-get install --assume-yes ca-certificates libssl1.1 libsqlite3-0 && \
    apt-get clean && \
    rm -fr -- /var/lib/apt/lists/* /var/cache/*

FROM sq-base AS sq

COPY --from=build /opt/usr/local/bin/sq /usr/local/bin/sq
COPY --from=build /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT ["/usr/local/bin/sq"]
