FROM python:3.14-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin certforge \
 && mkdir /data && chown certforge /data && chmod 700 /data

WORKDIR /srv/certforge
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

# Which build this is (shown in the web UI footer and on the CA page). Passed by the release workflow and CI.
ARG VERSION=dev
ARG REVISION=
RUN printf '%s\n' "$VERSION" > VERSION && printf '%s\n' "$REVISION" > REVISION

ENV CERTFORGE_DEPLOY=docker \
    CERTFORGE_DATA=/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER certforge
VOLUME /data
EXPOSE 443 80

# The server is HTTPS-only on 443 with a certificate we made ourselves, so check the socket
# and the health endpoint with verification off; this probe talks only to localhost.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import ssl,urllib.request as u; c=ssl.create_default_context(); c.check_hostname=False; c.verify_mode=ssl.CERT_NONE; import sys; sys.exit(0 if u.urlopen('https://127.0.0.1/healthz',context=c,timeout=4).read()==b'ok' else 1)"

CMD ["python", "-m", "app.server"]
