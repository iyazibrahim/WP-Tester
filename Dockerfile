FROM golang:1.25-bookworm AS gobuilder

ARG HTTPX_VERSION=v1.7.1
ARG SUBFINDER_VERSION=v2.7.0
ARG FFUF_VERSION=v2.1.0
ARG DALFOX_VERSION=v2.12.0
ARG KATANA_VERSION=v1.1.2
ARG GAU_VERSION=v2.2.4
ARG NUCLEI_VERSION=v3.3.8

ENV GOBIN=/go/bin

RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}
RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}
RUN CGO_ENABLED=0 go install -v github.com/ffuf/ffuf/v2@${FFUF_VERSION}
RUN CGO_ENABLED=0 go install -v github.com/hahwul/dalfox/v2@${DALFOX_VERSION}
# Katana's Linux build pulls in go-tree-sitter, which does not build with CGO disabled.
RUN CGO_ENABLED=1 go install -v github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}
RUN CGO_ENABLED=0 go install -v github.com/lc/gau/v2/cmd/gau@${GAU_VERSION}
RUN CGO_ENABLED=0 go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}

FROM rust:1.89-bookworm AS rustbuilder

RUN cargo install --locked feroxbuster

FROM debian:12-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/usr/local/bin:/opt/venv/bin:${PATH}"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-pip \
    ca-certificates \
    curl \
    git \
    wget \
    unzip \
    ruby \
    ruby-dev \
    perl \
    libxml-writer-perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libwww-perl \
    default-jre \
    procps \
    sqlmap \
    && rm -rf /var/lib/apt/lists/*

COPY --from=gobuilder /go/bin/httpx /usr/local/bin/httpx
COPY --from=gobuilder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=gobuilder /go/bin/ffuf /usr/local/bin/ffuf
COPY --from=gobuilder /go/bin/dalfox /usr/local/bin/dalfox
COPY --from=gobuilder /go/bin/katana /usr/local/bin/katana
COPY --from=gobuilder /go/bin/gau /usr/local/bin/gau
COPY --from=gobuilder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=rustbuilder /usr/local/cargo/bin/feroxbuster /usr/local/bin/feroxbuster

RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt /tmp/requirements.txt

RUN /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt && \
    /opt/venv/bin/pip install --no-cache-dir sslyze gunicorn arjun && \
    # wapiti3 pulls Python httpx, whose CLI would shadow ProjectDiscovery httpx
    rm -f /opt/venv/bin/httpx

# Bake Nuclei templates into the image (requires network at build time).
RUN nuclei -ut || nuclei -update-templates || true

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    gem install --no-document wpscan && \
    apt-get purge -y --auto-remove build-essential && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/tools/whatweb && \
    printf '#!/usr/bin/env bash\nexec ruby /opt/tools/whatweb/whatweb "$@"\n' >/usr/local/bin/whatweb && \
    chmod +x /usr/local/bin/whatweb

RUN git clone --depth 1 https://github.com/dionach/CMSmap.git /opt/tools/CMSmap && \
    if [ -f /opt/tools/CMSmap/requirements.txt ]; then \
        /opt/venv/bin/pip install --no-cache-dir -r /opt/tools/CMSmap/requirements.txt; \
    fi && \
    printf '#!/usr/bin/env bash\nexec python3 /opt/tools/CMSmap/cmsmap.py "$@"\n' >/usr/local/bin/cmsmap && \
    chmod +x /usr/local/bin/cmsmap

RUN git clone --depth 1 https://github.com/s0md3v/Corsy.git /opt/tools/Corsy && \
    if [ -f /opt/tools/Corsy/requirements.txt ]; then \
        /opt/venv/bin/pip install --no-cache-dir -r /opt/tools/Corsy/requirements.txt; \
    fi && \
    printf '#!/usr/bin/env bash\nexec python3 /opt/tools/Corsy/corsy.py "$@"\n' >/usr/local/bin/corsy && \
    chmod +x /usr/local/bin/corsy

RUN git clone --depth 1 https://github.com/OWASP/joomscan.git /opt/tools/joomscan && \
    printf '#!/usr/bin/env bash\nexec perl /opt/tools/joomscan/joomscan.pl "$@"\n' >/usr/local/bin/joomscan && \
    chmod +x /usr/local/bin/joomscan

RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/tools/commix && \
    printf '#!/usr/bin/env bash\nexec python3 /opt/tools/commix/commix.py "$@"\n' >/usr/local/bin/commix && \
    chmod +x /usr/local/bin/commix

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/tools/nikto && \
    printf '#!/usr/bin/env bash\nexec perl /opt/tools/nikto/program/nikto.pl "$@"\n' >/usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

# Ensure ProjectDiscovery httpx remains the default after any later pip installs.
RUN rm -f /opt/venv/bin/httpx

COPY . /app

RUN chmod +x /app/docker/entrypoint.sh && \
    find /app -maxdepth 1 -name "*.sh" -exec sed -i 's/\r$//' {} \; && \
    sed -i 's/\r$//' /app/docker/entrypoint.sh

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["app"]
