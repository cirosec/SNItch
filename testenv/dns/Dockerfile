# Minimal dnsmasq image for the SNItch test environment.
# Built locally so the config path and startup flags are predictable.
FROM alpine:3.20

RUN apk add --no-cache dnsmasq

# The rendered config is mounted at /etc/dnsmasq.conf by docker-compose.
EXPOSE 5353/udp

ENTRYPOINT ["dnsmasq"]
CMD ["-k", "--conf-file=/etc/dnsmasq.conf"]
