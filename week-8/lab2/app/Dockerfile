FROM python:3.9-bullseye

# Install compatible XML libraries
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libxml2-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        pkg-config \
        libtool \
        make && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY saml /app/saml


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]

