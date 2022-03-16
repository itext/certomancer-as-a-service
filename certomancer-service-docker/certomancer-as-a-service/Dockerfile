FROM python:3.10-slim

LABEL maintainer="Matthias Valvekens <matthias.valvekens@itextpdf.com>"

COPY requirements.txt /build/
RUN apt-get update && apt-get -y install uwsgi uwsgi-plugin-python3 && rm -rf /var/lib/apt/lists/*
RUN pip install -r /build/requirements.txt && rm -rf /build


COPY certomancer-uwsgi.ini /app/uwsgi.ini
COPY certomancer_aas.py wsgi.py /app/
COPY launch.sh /app/
RUN groupadd -g 777 nginx && useradd -u 777 -g nginx -s /bin/sh nginx

ENV CERTOMANCER_KEY_DIR /certomancer/keys
ENV CERTOMANCER_CONFIG /certomancer/certomancer.yml

WORKDIR /app

ENV PORT=6574

CMD ["./launch.sh"]