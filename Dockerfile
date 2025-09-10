FROM ubuntu:22.04
ARG OS-PASSWORD

ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive 
ENV TZ=Etc/UTC

# Install build/test deps (adjust as needed)
RUN ln -fs /usr/share/zoneinfo/$TZ /etc/localtime; \
    echo "$TZ" > /etc/timezone && \
    apt-get update && apt-get install -o Dpkg::Use-Pty=0 -y \
        python3 python3-pip git curl ca-certificates sudo  && \
    rm -rf /var/lib/apt/lists/*  && \
    apt clean

RUN pip install --upgrade pip setuptools wheel

# Set workdir
WORKDIR /app

COPY setup.sh /app
COPY requirements.txt /app

RUN ./setup.sh

COPY . /app

CMD ["./cicd/test.sh"]
