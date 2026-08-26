# Download pinned release binaries instead of compiling Go/Rust on the VPS.
FROM debian:12-slim AS tools

# Default amd64 when BuildKit does not inject TARGETARCH (classic docker build).
ARG TARGETARCH=amd64
ARG HTTPX_VERSION=v1.7.1
ARG SUBFINDER_VERSION=v2.7.0
ARG FFUF_VERSION=v2.1.0
ARG DALFOX_VERSION=v2.12.0
ARG KATANA_VERSION=v1.1.2
ARG GAU_VERSION=v2.2.4
ARG NUCLEI_VERSION=v3.3.8
ARG FEROXBUSTER_VERSION=v2.11.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/tools

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64|"") PD_ARCH=amd64; FEROX_ARCH=x86_64 ;; \
      arm64) PD_ARCH=arm64; FEROX_ARCH=aarch64 ;; \
      *) echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    strip_v() { printf '%s' "$1" | sed 's/^v//'; }; \
    HTTPX_VER="$(strip_v "${HTTPX_VERSION}")"; \
    SUBFINDER_VER="$(strip_v "${SUBFINDER_VERSION}")"; \
    FFUF_VER="$(strip_v "${FFUF_VERSION}")"; \
    KATANA_VER="$(strip_v "${KATANA_VERSION}")"; \
    GAU_VER="$(strip_v "${GAU_VERSION}")"; \
    NUCLEI_VER="$(strip_v "${NUCLEI_VERSION}")"; \
    mkdir -p /out; \
    echo "[tools] arch=${PD_ARCH} ferox=${FEROX_ARCH}"; \
    echo "[tools] httpx"; \
    curl -fsSL -o httpx.zip \
      "https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VER}_linux_${PD_ARCH}.zip"; \
    unzip -qo httpx.zip httpx && install -m 0755 httpx /out/httpx; \
    echo "[tools] subfinder"; \
    curl -fsSL -o subfinder.zip \
      "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VER}_linux_${PD_ARCH}.zip"; \
    unzip -qo subfinder.zip subfinder && install -m 0755 subfinder /out/subfinder; \
    echo "[tools] ffuf"; \
    curl -fsSL -o ffuf.tgz \
      "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VER}_linux_${PD_ARCH}.tar.gz"; \
    tar -xzf ffuf.tgz ffuf && install -m 0755 ffuf /out/ffuf; \
    echo "[tools] dalfox"; \
    curl -fsSL -o dalfox.tgz \
      "https://github.com/hahwul/dalfox/releases/download/${DALFOX_VERSION}/dalfox-linux-${PD_ARCH}.tar.gz"; \
    # Release tarball member is dalfox-linux-<arch>, not plain "dalfox".
    tar -xzf dalfox.tgz "dalfox-linux-${PD_ARCH}" && \
      install -m 0755 "dalfox-linux-${PD_ARCH}" /out/dalfox; \
    echo "[tools] katana"; \
    curl -fsSL -o katana.zip \
      "https://github.com/projectdiscovery/katana/releases/download/${KATANA_VERSION}/katana_${KATANA_VER}_linux_${PD_ARCH}.zip"; \
    unzip -qo katana.zip katana && install -m 0755 katana /out/katana; \
    echo "[tools] gau"; \
    curl -fsSL -o gau.tgz \
      "https://github.com/lc/gau/releases/download/${GAU_VERSION}/gau_${GAU_VER}_linux_${PD_ARCH}.tar.gz"; \
    tar -xzf gau.tgz gau && install -m 0755 gau /out/gau; \
    echo "[tools] nuclei"; \
    curl -fsSL -o nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VER}_linux_${PD_ARCH}.zip"; \
    unzip -qo nuclei.zip nuclei && install -m 0755 nuclei /out/nuclei; \
    echo "[tools] feroxbuster"; \
    curl -fsSL -o ferox.zip \
      "https://github.com/epi052/feroxbuster/releases/download/${FEROXBUSTER_VERSION}/${FEROX_ARCH}-linux-feroxbuster.zip"; \
    unzip -qo ferox.zip feroxbuster && install -m 0755 feroxbuster /out/feroxbuster; \
    ls -la /out

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

COPY --from=tools /out/httpx /usr/local/bin/httpx
COPY --from=tools /out/subfinder /usr/local/bin/subfinder
COPY --from=tools /out/ffuf /usr/local/bin/ffuf
COPY --from=tools /out/dalfox /usr/local/bin/dalfox
COPY --from=tools /out/katana /usr/local/bin/katana
COPY --from=tools /out/gau /usr/local/bin/gau
COPY --from=tools /out/nuclei /usr/local/bin/nuclei
COPY --from=tools /out/feroxbuster /usr/local/bin/feroxbuster

RUN python3 -m venv /opt/venv && \
    python3 -m venv /opt/scanner-venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/scanner-venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt /tmp/requirements.txt
COPY requirements-scanners.txt /tmp/requirements-scanners.txt
COPY docker/patch_wapiti_gettext.py /tmp/patch_wapiti_gettext.py

# App venv: Flask 3 / gunicorn only (never install wapiti here).
RUN /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

# Native build toolchain for scanner wheels (zstandard/mitmproxy) and WPScan gem, then purge.
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential python3-dev && \
    /opt/scanner-venv/bin/pip install --no-cache-dir -r /tmp/requirements-scanners.txt && \
    rm -f /opt/scanner-venv/bin/httpx /opt/venv/bin/httpx && \
    printf '#!/usr/bin/env bash\nexec /opt/scanner-venv/bin/wapiti "$@"\n' >/usr/local/bin/wapiti && \
    printf '#!/usr/bin/env bash\nexec /opt/scanner-venv/bin/droopescan "$@"\n' >/usr/local/bin/droopescan && \
    printf '#!/usr/bin/env bash\nexec /opt/scanner-venv/bin/sslyze "$@"\n' >/usr/local/bin/sslyze && \
    printf '#!/usr/bin/env bash\nexec /opt/scanner-venv/bin/arjun "$@"\n' >/usr/local/bin/arjun && \
    chmod +x /usr/local/bin/wapiti /usr/local/bin/droopescan /usr/local/bin/sslyze /usr/local/bin/arjun && \
    /opt/scanner-venv/bin/python /tmp/patch_wapiti_gettext.py && \
    gem install --no-document wpscan && \
    apt-get purge -y --auto-remove build-essential python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Bake Nuclei templates into the image (requires network at build time).
RUN nuclei -ut || nuclei -update-templates || true

RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/tools/whatweb && \
    printf '#!/usr/bin/env bash\nexec ruby /opt/tools/whatweb/whatweb "$@"\n' >/usr/local/bin/whatweb && \
    chmod +x /usr/local/bin/whatweb

RUN git clone --depth 1 https://github.com/dionach/CMSmap.git /opt/tools/CMSmap && \
    if [ -f /opt/tools/CMSmap/requirements.txt ]; then \
        /opt/scanner-venv/bin/pip install --no-cache-dir -r /opt/tools/CMSmap/requirements.txt; \
    fi && \
    printf '#!/usr/bin/env bash\nexec /opt/scanner-venv/bin/python /opt/tools/CMSmap/cmsmap.py "$@"\n' >/usr/local/bin/cmsmap && \
    chmod +x /usr/local/bin/cmsmap

RUN git clone --depth 1 https://github.com/s0md3v/Corsy.git /opt/tools/Corsy && \
    if [ -f /opt/tools/Corsy/requirements.txt ]; then \
        /opt/scanner-venv/bin/pip install --no-cache-dir -r /opt/tools/Corsy/requirements.txt; \
    fi && \
    printf '#!/usr/bin/env bash\nexec /opt/scanner-venv/bin/python /opt/tools/Corsy/corsy.py "$@"\n' >/usr/local/bin/corsy && \
    chmod +x /usr/local/bin/corsy

RUN git clone --depth 1 https://github.com/OWASP/joomscan.git /opt/tools/joomscan && \
    printf '#!/usr/bin/env bash\nexec perl /opt/tools/joomscan/joomscan.pl "$@"\n' >/usr/local/bin/joomscan && \
    chmod +x /usr/local/bin/joomscan

RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/tools/commix && \
    printf '#!/usr/bin/env bash\nexec /opt/scanner-venv/bin/python /opt/tools/commix/commix.py "$@"\n' >/usr/local/bin/commix && \
    chmod +x /usr/local/bin/commix

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/tools/nikto && \
    printf '#!/usr/bin/env bash\nexec perl /opt/tools/nikto/program/nikto.pl "$@"\n' >/usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

# Ensure ProjectDiscovery httpx remains the default after any later pip installs.
RUN rm -f /opt/venv/bin/httpx /opt/scanner-venv/bin/httpx

COPY . /app

RUN chmod +x /app/docker/entrypoint.sh /app/docker/healthcheck.sh && \
    find /app -maxdepth 1 -name "*.sh" -exec sed -i 's/\r$//' {} \; && \
    sed -i 's/\r$//' /app/docker/entrypoint.sh /app/docker/healthcheck.sh

EXPOSE 5000

HEALTHCHECK --interval=60s --timeout=15s --start-period=60s --retries=5 \
    CMD ["/app/docker/healthcheck.sh"]

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["app"]
