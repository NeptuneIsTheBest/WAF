ARG WAF_IMAGE=debian:12
FROM ${WAF_IMAGE}
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus bash ca-certificates curl jq tar gzip coreutils \
    iproute2 util-linux passwd python3 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
