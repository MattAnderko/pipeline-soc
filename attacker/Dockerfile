FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    netcat-openbsd \
    nmap \
    ssh \
    git \
    openjdk-11-jdk \
    maven \
    build-essential \
    djvulibre-bin \
    jq \
    vim \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Build marshalsec (LDAP server for Log4Shell)
RUN cd /opt && \
    git clone https://github.com/mbechler/marshalsec.git && \
    cd marshalsec && \
    mvn clean package -DskipTests -q

# Generate SSH key for persistence phase
RUN ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N "" -q

WORKDIR /opt

CMD ["/bin/bash"]
