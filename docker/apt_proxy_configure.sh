#!/usr/bin/env bash

if [[ -n "${APT_PROXY}" ]]; then
  cat > /etc/apt/apt.conf.d/01proxy <<EOF
Acquire::HTTP::Proxy "${APT_PROXY}";
Acquire::HTTPS::Proxy false;
EOF
  cat /etc/apt/apt.conf.d/01proxy
fi

exit 0
