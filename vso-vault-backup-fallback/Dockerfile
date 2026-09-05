FROM alpine:3.22

LABEL \
  io.hass.version="1.1.9" \
  io.hass.type="app" \
  io.hass.arch="amd64|aarch64"

RUN apk add --no-cache samba-client python3

COPY rootfs/usr/bin/vso_fallback.py /usr/bin/vso_fallback.py

RUN chmod 0755 /usr/bin/vso_fallback.py

CMD ["/usr/bin/vso_fallback.py"]
