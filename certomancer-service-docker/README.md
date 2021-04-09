# Certomancer-as-a-Service


Run

```
$ docker-compose build
$ docker-compose up
```

as an account with access to the docker daemon.


Once the service is running, try POSTing some ad hoc config to it using `curl`:

```
curl --data-binary @ad-hoc-samples/typical-ocsp-scenario.yml 'http://localhost:9000/config' 
```

If all is well, you should receive a large amount of JSON data as a response.


# General configuration

Certomancer docs: https://github.com/MatthiasValvekens/certomancer/blob/master/docs/config.md

The ad-hoc mode is not a feature of Certomancer itself, but rather an extension implemented here. Further details on the ad-hoc mode will follow once things are a bit more stable.

