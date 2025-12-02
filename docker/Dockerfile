# Dockerfile for Cyber-AutoAgent (Kali Rolling base)

ARG APT_PROXY

FROM --platform=$BUILDPLATFORM golang:1.25 AS gobuild
ARG TARGETARCH
ARG BUILDPLATFORM
ENV DEBIAN_FRONTEND=noninteractive
ENV GOOS=linux GOARCH=$TARGETARCH
COPY docker/apt_proxy_configure.sh /tmp/
RUN /tmp/apt_proxy_configure.sh && \
    apt-get update && apt-get install -y --no-install-recommends build-essential pkg-config git ca-certificates &&\
    if [ "$BUILDPLATFORM" = "linux/amd64" ]; then apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross; fi &&\
    if [ "$BUILDPLATFORM" = "linux/arm64" ]; then apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu g++-x86-64-linux-gnu libc6-dev-amd64-cross; fi
ENV CGO_ENABLED=1
ADD docker/packages-go.sh /tmp
RUN /tmp/packages-go.sh

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="Cyber-AutoAgent"
LABEL org.opencontainers.image.description="Autonomous AI agent for ethical security assessments"
LABEL org.opencontainers.image.version="0.1.5"
LABEL org.opencontainers.image.source="https://github.com/cyber-autoagent/cyber-autoagent"
LABEL org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive

COPY docker/apt_proxy_configure.sh docker/apt_proxy_clean.sh /tmp/

RUN set -eux; \
    /tmp/apt_proxy_configure.sh && \
    mirrors="ftp.acc.umu.se/mirror/kali.org/kali mirror.math.princeton.edu/pub/kali kali.mirror.garr.it/mirrors/kali mirror.pit.teraswitch.com/kali"; \
    success=0; \
    for mirror in $mirrors; do \
        echo "deb http://$mirror kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list; \
        if apt update; then \
            echo "Using Kali mirror: $mirror"; \
            success=1; \
            break; \
        fi; \
    done; \
    if [ "$success" -ne 1 ]; then \
        echo "ERROR: apt update failed for all configured mirrors" >&2; \
        exit 1; \
    fi;

RUN set -eux; \
    mirrors="ftp.acc.umu.se/mirror/kali.org/kali mirror.math.princeton.edu/pub/kali kali.mirror.garr.it/mirrors/kali mirror.pit.teraswitch.com/kali"; \
    success=0; \
    for mirror in $mirrors; do \
        echo "deb http://$mirror kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list; \
        if apt update; then \
            echo "Using Kali mirror: $mirror"; \
            success=1; \
            break; \
        fi; \
    done; \
    if [ "$success" -ne 1 ]; then \
        echo "ERROR: apt update failed for all configured mirrors" >&2; \
        exit 1; \
    fi; \
    apt install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-pip \
    python-is-python3 \
    pipx \
    # Java runtime for ZAP/Burp
    openjdk-21-jre-headless \
    # Binary analysis tools
    binutils \
    # Security tools
    nmap \
    sqlmap \
    curl \
    netcat-traditional \
    tcpdump \
    git \
    perl \
    gnupg2 \
    wget \
    # Perl SSL/TLS modules for Nikto HTTPS support
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libcrypt-ssleay-perl \
    libssl-dev \
    ca-certificates \
    # Network tools
    iputils-ping \
    dnsutils \
    iproute2 \
    net-tools \
    traceroute \
    # Additional essential tools
    jq \
    unzip \
    unrar \
    tree \
    sudo \
    file \
    xxd \
    # Web scanners
    nikto \
    whatweb \
    wafw00f \
    zaproxy \
    burpsuite \
    # Recon and DNS
    amass \
    subfinder \
    dnsrecon \
    dnsenum \
    theharvester \
    # Web fuzzing & directories
    ffuf \
    feroxbuster \
    dirb \
    arjun \
    wapiti \
    wfuzz \
    wpscan \
    # Network scanning
    masscan \
    naabu \
    # SMB/NetBIOS
    smbclient \
    smbmap \
    nbtscan \
    python3-impacket \
    # SNMP/Discovery
    arp-scan \
    ike-scan \
    onesixtyone \
    snmpcheck \
    netdiscover \
    # Utilities
    hping3 \
    socat \
    proxychains4 \
    sslscan \
    seclists \
    # Web app helpers
    commix \
    xsser \
    hashid \
    # ProjectDiscovery vuln scanner
    nuclei \
    # Auth/bruteforce
    hydra \
    medusa \
    ncrack \
    hashcat \
    john \
    # Content and metadata
    libimage-exiftool-perl \
    cewl \
    # WebDAV testing
    cadaver \
    davtest \
    # SSL/TLS testing
    sslyze \
    testssl.sh \
    # Extra recon/webapp scanners
    gospider \
    httprobe \
    subjack \
    knockpy \
    joomscan \
    wig \
    uniscan \
    dirsearch \
    skipfish \
    enum4linux \
    # Offensive frameworks
    metasploit-framework \
    # Go toolchain for ProjectDiscovery/tomnomnom tools
    golang \
    # Rust toolchain for building Python packages with native extensions
    rustc \
    cargo \
    # Node.js for GraphQL tools
    nodejs \
    npm \
    # Python build tools for pip packages
    python3-dev \
    build-essential \
    # Dependencies for pwntools/unicorn
    cmake \
    pkg-config \
    libglib2.0-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    # Binary Exploitation & Reversing
    gdb \
    ltrace \
    strace \
    radare2 \
    # Steganography & Forensics
    steghide \
    binwalk \
    foremost \
    # Ruby for zsteg/whatweb
    ruby-full \
    && apt clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Provide symlinks from Ruby vendor_ruby so WhatWeb runs without error
RUN set -eux; \
    if command -v whatweb >/dev/null 2>&1; then \
      mkdir -p /usr/bin/lib; \
      # Link all vendor_ruby top-level files
      if ls /usr/lib/ruby/vendor_ruby/*.rb >/dev/null 2>&1; then \
        ln -sf /usr/lib/ruby/vendor_ruby/*.rb /usr/bin/lib/; \
      fi; \
    fi

COPY --from=gobuild /usr/local/bin/* /usr/local/bin/

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:0.9.14 /uv /usr/local/bin/uv

# Install Ruby gems
RUN gem install zsteg

# Install additional security tools
# GraphQL Clairvoyance - GraphQL schema enumeration
RUN git clone --depth=1 https://github.com/nikitastupin/clairvoyance.git /opt/clairvoyance || true && \
    if [ -d /opt/clairvoyance ]; then \
      cd /opt/clairvoyance && \
      python3 -m venv venv && \
      . venv/bin/activate && \
      pip install . || true; \
    fi

# JWT Tool - JWT analysis and manipulation
RUN git clone --depth=1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool || true && \
    if [ -f /opt/jwt_tool/jwt_tool.py ]; then chmod +x /opt/jwt_tool/jwt_tool.py; fi

# tplmap - Server-Side Template Injection scanner
RUN git clone --depth=1 https://github.com/epinna/tplmap.git /opt/tplmap || true && \
    if [ -f /opt/tplmap/tplmap.py ]; then chmod +x /opt/tplmap/tplmap.py; fi

# Gopherus - SSRF payload generator
RUN git clone --depth=1 https://github.com/tarunkant/Gopherus.git /opt/gopherus || true && \
    if [ -f /opt/gopherus/gopherus.py ]; then chmod +x /opt/gopherus/gopherus.py; fi

# PHPGGC - PHP Generic Gadget Chains
RUN git clone --depth=1 https://github.com/ambionics/phpggc.git /opt/phpggc || true && \
    if [ -f /opt/phpggc/phpggc ]; then chmod +x /opt/phpggc/phpggc; fi

# Ysoserial - Java Deserialization (download jar)
RUN mkdir -p /opt/ysoserial && \
    wget -qO /opt/ysoserial/ysoserial.jar https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar || true

# Install Python packages for our new tools (use --break-system-packages for Kali)
RUN pip3 install --break-system-packages requests aiohttp jinja2 'httpx[cli]' ratelimit pycryptodomex ropgadget ropper

# Create wrapper scripts for easy access
RUN ([ -d /opt/clairvoyance ] && echo '#!/bin/bash\ncd /opt/clairvoyance && source venv/bin/activate && python -m clairvoyance "$@"' > /usr/local/bin/clairvoyance && chmod +x /usr/local/bin/clairvoyance) || true && \
    ([ -f /opt/jwt_tool/jwt_tool.py ] && echo '#!/bin/bash\npython3 /opt/jwt_tool/jwt_tool.py "$@"' > /usr/local/bin/jwt-tool && chmod +x /usr/local/bin/jwt-tool) || true && \
    ([ -f /opt/tplmap/tplmap.py ] && echo '#!/bin/bash\npython3 /opt/tplmap/tplmap.py "$@"' > /usr/local/bin/tplmap && chmod +x /usr/local/bin/tplmap) || true && \
    ([ -f /opt/gopherus/gopherus.py ] && echo '#!/bin/bash\npython3 /opt/gopherus/gopherus.py "$@"' > /usr/local/bin/gopherus && chmod +x /usr/local/bin/gopherus) || true && \
    ([ -f /opt/phpggc/phpggc ] && ln -sf /opt/phpggc/phpggc /usr/local/bin/phpggc) || true && \
    (echo '#!/bin/bash\njava -jar /opt/ysoserial/ysoserial.jar "$@"' > /usr/local/bin/ysoserial && chmod +x /usr/local/bin/ysoserial) || true

# Install NetExec (modern CrackMapExec) from source
RUN git clone --depth=1 https://github.com/Pennyw0rth/NetExec.git /opt/netexec && \
    cd /opt/netexec && \
    pip3 install --break-system-packages . && \
    ln -sf /opt/netexec/nxc.py /usr/local/bin/netexec || true

# Install Evil-WinRM via gem
RUN gem install evil-winrm

# Install XSStrike
RUN git clone --depth=1 https://github.com/s0md3v/XSStrike.git /opt/xsstrike && \
    pip3 install --break-system-packages -r /opt/xsstrike/requirements.txt && \
    chmod +x /opt/xsstrike/xsstrike.py && \
    ln -sf /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike

# Install PEASS-ng (Privilege Escalation)
RUN mkdir -p /opt/peass && \
    wget -qO /opt/peass/linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh && \
    chmod +x /opt/peass/linpeas.sh && \
    ln -sf /opt/peass/linpeas.sh /usr/local/bin/linpeas

# Install Sliver (C2 Framework - Client only) - Optional, may fail on ARM64
RUN curl https://sliver.sh/install | bash || true

# Install BloodHound Python (AD Analysis)
RUN pipx install bloodhound

# Install Certipy (AD CS Abuse)
RUN pipx install certipy-ad

# Install Coercer (AD Coercion)
RUN pipx install coercer

# Install Responder (LLMNR/NBT-NS Poisoning)
RUN git clone --depth=1 https://github.com/lgandx/Responder.git /opt/responder && \
    ln -sf /opt/responder/Responder.py /usr/local/bin/responder

# Install TruffleHog (Secret Scanning)
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install GitTools (Git Dumper/Extractor)
RUN git clone --depth=1 https://github.com/internetwache/GitTools.git /opt/gittools && \
    chmod +x /opt/gittools/Dumper/gitdumper.sh /opt/gittools/Extractor/extractor.sh && \
    ln -sf /opt/gittools/Dumper/gitdumper.sh /usr/local/bin/gitdumper && \
    ln -sf /opt/gittools/Extractor/extractor.sh /usr/local/bin/gitextractor

# Install PwnCat-CS (Advanced Reverse Shell Handler)
RUN pipx install pwncat-cs

# Install RsaCtfTool (RSA Attacks) - requires GMP/MPFR libraries
RUN apt update && apt install -y --no-install-recommends \
    libgmp-dev libmpfr-dev libmpc-dev && \
    apt clean && rm -rf /var/lib/apt/lists/* && \
    git clone --depth=1 https://github.com/RsaCtfTool/RsaCtfTool.git /opt/rsactftool && \
    cd /opt/rsactftool && \
    pip3 install --break-system-packages -r requirements.txt && \
    ln -sf /opt/rsactftool/RsaCtfTool.py /usr/local/bin/rsactftool || true

# Install Volatility3 (Memory Forensics) - Optional
RUN git clone --depth=1 --depth=1 https://github.com/volatilityfoundation/volatility3.git /opt/volatility3 && \
    cd /opt/volatility3 && \
    pip3 install --break-system-packages . && \
    ln -sf /opt/volatility3/vol.py /usr/local/bin/vol || true

RUN useradd --create-home --shell /bin/bash cyberagent && \
    usermod -aG sudo cyberagent && \
    echo 'cyberagent ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers && \
    mkdir -p /app/evidence /app/logs /home/cyberagent/go && \
    chmod 755 /app/evidence /app/logs && \
    chown -R cyberagent:cyberagent /home/cyberagent/go

# Set working directory
WORKDIR /app

# Copy dependency descriptors and source
COPY pyproject.toml ./
COPY uv.lock* ./
COPY src/ ./src/

# Install Python dependencies into a local venv
RUN uv sync --no-dev

# Install and build React terminal interface (default UI)
RUN cd /app/src/modules/interfaces/react && \
    npm install && \
    npm run build && \
    chown -R cyberagent:cyberagent /app/src/modules/interfaces/react

# Install chromium browser for playwright to use
RUN env PLAYWRIGHT_HOST_PLATFORM_OVERRIDE="debian13-$(dpkg --print-architecture | sed 's/amd/x/')" \
    PLAYWRIGHT_BROWSERS_PATH=/home/cyberagent/.cache/ms-playwright \
    uv run playwright install chromium --with-deps && \
    chown -R cyberagent:cyberagent /home/cyberagent/.cache && \
    CHROME_BIN=$(find /home/cyberagent/.cache/ms-playwright -type f \( -name chrome -o -name chromium \) | head -n 1) && \
    if [ -n "$CHROME_BIN" ]; then mkdir -p /usr/lib/chromium && ln -sf "$CHROME_BIN" /usr/lib/chromium/chromium; fi && \
    apt clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

RUN /tmp/apt_proxy_clean.sh

# Environment
ENV GOPATH="/home/cyberagent/go"
ENV GOCACHE="/home/cyberagent/go/.cache"
ENV PATH="/app/.venv/bin:/home/cyberagent/go/bin:$PATH"
ENV PLAYWRIGHT_BROWSERS_PATH="/home/cyberagent/.cache/ms-playwright"
ENV PYTHONPATH="/usr/lib/python3/dist-packages:/app/src"

# Persist important directories
VOLUME ["/app/evidence", "/app/logs"]

# Expose port for any web interfaces 
EXPOSE 8080

# Health check (always-healthy placeholder; app exposes no service port by default)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default entrypoint: React terminal (which spawns Python agent as subprocess)
# Falls back to direct Python execution if given --python-direct flag
ENTRYPOINT ["node", "/app/src/modules/interfaces/react/dist/index.js"]
