FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY . /app

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    dnsutils \
    iputils-ping \
    net-tools \
    git \
    nmap \
    naabu \
    whatweb \
    nuclei \
    && apt-get clean

RUN mkdir -p /opt/nuclei-templates && \
    git clone https://github.com/projectdiscovery/nuclei-templates /opt/nuclei-templates

EXPOSE 8000

CMD ["python3", "main.py"]
