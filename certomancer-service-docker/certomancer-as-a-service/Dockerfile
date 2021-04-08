FROM tiangolo/uwsgi-nginx:python3.8

LABEL maintainer="Matthias Valvekens <matthias.valvekens@itextpdf.com>"

# Temporary measure!
COPY certomancer-0.3.0.dev1-py3-none-any.whl requirements.txt /build/
RUN pip install /build/certomancer-0.3.0.dev1-py3-none-any.whl
# end temporary code

RUN pip install -r /build/requirements.txt && rm -rf /build

COPY certomancer-uwsgi.ini /app/uwsgi.ini
COPY certomancer_aas.py wsgi.py /app/

ENV CERTOMANCER_KEY_DIR /certomancer/keys
ENV CERTOMANCER_CONFIG /certomancer/certomancer.yml