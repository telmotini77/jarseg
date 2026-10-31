FROM python:3.11-slim-bookworm
# libpcap: scapy compiles the BPF capture filter with it.
# nftables: the active response blocks attackers in the host firewall.
RUN apt-get update \
  && apt-get install -y --no-install-recommends libpcap0.8 nftables \
  && rm -rf /var/lib/apt/lists/*
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY cyberseg_engine ./cyberseg_engine
CMD ["python", "-m", "cyberseg_engine.main"]
