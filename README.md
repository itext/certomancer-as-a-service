# Certomancer-as-a-Service


This repository contains two components:

 - A containerised version of [Certomancer](https://github.com/MatthiasValvekens/certomancer) with live configuration management support.
 - A Java client with some additional integrations that make it easier to use the container in automated tests (in a Java project).


## The Certomancer-as-a-Service container

The sample `docker-compose.yml` file in `certomancer-service-docker` declares three containers:

 - A `certomancer-as-a-service` container that exposes the Certomancer instance as a WSGI application using uWSGI.
 - A `redis` container to serve as the backend for the configuration management logic in the `certomancer-as-a-service` application.
 - A `nginx` container to expose a minimal HTTP frontend for the `certomancer-as-a-service` container.

The setup also includes a `sample-cfg` directory with some sample key pairs and configuration.


### Basic setup


To spin up the sample config, change to the `certomancer-service-docker` folder and run

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


### Advanced setup

If you already have a `nginx` server running on the machine on which you intend to deploy the container, you may wish to have that server handle traffic to the Certomancer-as-a-Service application, instead of routing it to a dedicated `nginx` container (as is the case in the sample config). Note that this requires the `ngx_http_uwsgi_module` to be enabled.


In its most simple form, this is what the configuration of such a frontend looks like.

```
server {
    listen 80;
    location / {
        include uwsgi_params;
        uwsgi_pass INTERNAL_IP_OF_CERTOMANCER_CONTAINER:PORT;
    }
}
```

Note: if you decide to rewrite any URLs before passing them to the Certomancer container, please make sure to set up the [prefix for generated URLs in PKIX data](https://github.com/MatthiasValvekens/certomancer/blob/master/docs/config.md#general-structure) to account for that.
The `external-url-prefix` parameter should reflect the base URL to the Certomancer application, as seen from the point of view of the client.


In addition to replacing the `nginx` container with your own `nginx` server, you can of course also supply your own configuration to the `certomancer-as-a-service` container. The application reads its configuration from `/certomancer` (in the sample `docker-compose` setup, the `certomancer-service-docker/sample-cfg` directory is mounted at that location).
The `/certomancer` directory should contain at least a `certomancer.yml` file with some global config (e.g. declaring key sets), and a `keys` directory with available key files.
If you need inspiration, take a look at the files in the sample config directory.


## Test client integrations for Java

This Maven project supplies some Java client-side tooling for use with a Certomancer-as-a-Service container.

It has two subprojects:

 - `certomancer-config`: basic, framework-neutral abstractions to handle the process of submitting configuration to the Certomancer container, and decoding responses from the configuration API.
 - `certomancer-junit`: further integration to avoid boilerplate in JUnit tests that rely on Certomancer.


### Setting up shop


Maven dependency:
```xml
<dependency>
    <groupId>com.itextpdf</groupId>
    <artifactId>certomancer-config</artifactId>
    <version>1.0-SNAPSHOT</version>
    <scope>test</scope>
</dependency>
```

Using dynamic certificates & trust services supplied by Certomancer requires a `CertomancerConfig`.
If the instance you want to talk to listens at `http://localhost:9000`, this is all you have to do:

```java
CertomancerConfigManager manager = new CertomancerConfigManager(new URL("http://localhost:9000/config"));
CertomancerContext c = manager.submitConfiguration(yamlConfig);
```

In a Cucumber rule, that might look like this:

```java
    public static final String CERTOMANCER_URL = "http://localhost:9000/config";

    @Given("^a Certomancer architecture defined by '(.*)'$")
    public void setCertomancerPKI(String configFile) throws IOException {
        Path configPath = Paths.get(srcFolder, "certomancer", configFile);
        String yamlConfig = new String(Files.readAllBytes(configPath), Charsets.UTF_8);
        CertomancerContext c = new CertomancerConfigManager(new URL(CERTOMANCER_URL)).submitConfiguration(yamlConfig);
        context.set("certomancerContext", c);
    }
```

The `CertomancerContext` API is pretty straightforward: the `get()` method retrieves a `CertPackage` object containing a certificate, the corresponding private key and a list of other relevant certificates (a possible chain of trust, which may or may not be in the right order).

If you're looking to use this tool in JUnit tests, read on.


### JUnit 4 integration

If you ever want to use Certomancer in JUnit tests, add the `certomancer-junit` module as a dependency.
This module adds another layer of convenience by defining a JUnit rule to load a Certomancer config for an entire test class.
Since tests relying on Certomancer won't run without a Certomancer container available, this rule handles both resource provisioning and automatic skipping of tests if Certomancer is not configured.

```java
public class SomeTest {
    @ClassRule
    public static final CertomancerResource CERTOMANCER = new CertomancerResource("typical-ocsp-scenario.yml");

    // tests go here
}

```
Use `CERTOMANCER.getContext()` to get access to the `CertomancerContext`.

This JUnit rule loads test scenarios from the classpath (the above invocation would look for a resource named `certomancer/typical-ocsp-scenario.yml`).

The configuration URL to use is read off from the `CERTOMANCER_CONFIG_URL` environment variable. Tests that depend on a `CertomancerResource` will be ignored if said environment variable is not set.
