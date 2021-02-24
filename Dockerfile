FROM python:3.8-buster

RUN apt-get update -y
RUN apt-get install --fix-missing -y libxml2-dev libxmlsec1-dev libxmlsec1-openssl

RUN mkdir -p /var/log/fairdata-sso
RUN mkdir -p /opt/fairdata/python3/bin

RUN ln -s /usr/local/bin/python /opt/fairdata/python3/bin/python3.8

RUN groupadd nginx

ENV SSO_ROOT="/app"
ENV SSO_CONFIG="/etc/fairdata-sso/config.json"
ENV SSO_SAML_CONFIG="/etc/fairdata-sso/saml.json"

WORKDIR /app

COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt

COPY . .

EXPOSE 5000

CMD ["flask", "run"]
