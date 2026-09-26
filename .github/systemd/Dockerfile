ARG WAF_IMAGE=debian:12
FROM ${WAF_IMAGE}
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus bash ca-certificates curl jq tar gzip coreutils \
    iproute2 util-linux passwd python3 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
# Credential mounts must propagate between systemd's internal mount namespaces.
# https://github.com/systemd/systemd/issues/38103
CMD ["/bin/sh", "-c", "mount --make-rshared /run && exec /sbin/init"]
