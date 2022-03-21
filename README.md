# Certomancer-as-a-Service: test client integrations for Java

This Maven project supplies some client-side tooling for use with a [Certomancer-as-a-Service](https://git.itextsupport.com/projects/RESEARCH/repos/certomancer-as-a-service/browse) container running on the local network or machine.


## Setting up shop


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

The `CertomancerContext` API is pretty straightforward: the `get()` method retrieves a `CertPackage` object containing a certificate, the corresponding private key and a list of other relevant certificates
(a possible chain of trust, which may or may not be in the right order).


## JUnit 4 integration

If you ever want to use Certomancer in JUnit tests, add the `certomancer-junit` module as a dependency.
Since these tests won't run without a Certomancer container available, the `certomancer-junit` module adds another layer of convenience by defining a JUnit rule to load a Certomancer config for an entire test class.
This rule handles both resource provisioning and automatic skipping of tests if Certomancer is not configured.

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
