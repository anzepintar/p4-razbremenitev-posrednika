FROM client:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium firefox-esr libnss3-tools ca-certificates \
        fonts-liberation fonts-noto-core fonts-noto-color-emoji \
        libgl1 libegl1 \
        xvfb x11vnc openbox novnc websockify x11-utils \
    && rm -rf /var/lib/apt/lists/*

COPY policies/firefox.json /etc/firefox-esr/policies/policies.json
COPY policies/firefox.json /usr/lib/firefox-esr/distribution/policies.json
COPY policies/chromium.json /etc/chromium/policies/managed/diploma.json
COPY openbox/menu.xml /etc/xdg/openbox/menu.xml

RUN ln -s /opt/traffic/browser/chromium.sh /usr/local/bin/diploma-chromium \
    && ln -s /opt/traffic/browser/firefox.sh /usr/local/bin/diploma-firefox

CMD ["sleep", "infinity"]
