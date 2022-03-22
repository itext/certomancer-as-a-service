FROM python:3.9-slim as buildimage
# Spin up a fresh image to build uwsgi against the system python

RUN apt-get update && apt-get -y install python3-dev g++ && rm -rf /var/lib/apt/lists/*
RUN pip wheel --wheel-dir=/wheels uwsgi

# Throw out the build image and start over
FROM python:3.9-slim
LABEL maintainer="Matthias Valvekens <matthias.valvekens@itextpdf.com>"


COPY --from=buildimage /wheels /build

COPY requirements.txt /build/
RUN pip install --no-cache-dir /build/*.whl -r /build/requirements.txt && rm -rf /build


COPY certomancer-uwsgi.ini /app/uwsgi.ini
COPY certomancer_aas.py wsgi.py /app/
COPY launch.sh /app/
RUN groupadd -g 777 nginx && useradd -u 777 -g nginx -s /bin/sh nginx

ENV CERTOMANCER_KEY_DIR /certomancer/keys
ENV CERTOMANCER_CONFIG /certomancer/certomancer.yml

WORKDIR /app

ENV PORT=6574

CMD ["./launch.sh"]
