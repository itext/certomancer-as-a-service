FROM tiangolo/uwsgi-nginx:python3.8

LABEL maintainer="Matthias Valvekens <matthias.valvekens@itextpdf.com>"

COPY requirements.txt /build/
RUN pip install -r /build/requirements.txt && rm -rf /build


COPY certomancer-uwsgi.ini /app/uwsgi.ini
COPY certomancer_aas.py wsgi.py /app/

ENV CERTOMANCER_KEY_DIR /certomancer/keys
ENV CERTOMANCER_CONFIG /certomancer/certomancer.yml
