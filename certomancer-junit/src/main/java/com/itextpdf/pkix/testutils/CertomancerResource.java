package com.itextpdf.pkix.testutils;

import com.itextpdf.test.certomancer.CertomancerConfigManager;
import com.itextpdf.test.certomancer.CertomancerContext;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assume;
import org.junit.rules.ExternalResource;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class CertomancerResource extends ExternalResource {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final String configResourceName;
    private CertomancerContext certomancerContext = null;

    public CertomancerResource(String configResourceName) {
        this.configResourceName = configResourceName;
    }

    protected void before() throws IOException {
        String configUrl = System.getenv().get("CERTOMANCER_CONFIG_URL");
        Assume.assumeNotNull(configUrl);  // skip tests if env var is not present
        CertomancerConfigManager manager = new CertomancerConfigManager(new URL(configUrl));
        InputStream is = CertomancerResource.class.getClassLoader()
                .getResourceAsStream("certomancer/" + this.configResourceName);
        if(is == null) {
            throw new FileNotFoundException();
        }
        // Java 9+, but eh
        String yamlConfig = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        this.certomancerContext = manager.submitConfiguration(yamlConfig);
    }

    public CertomancerContext getContext() {
        if(this.certomancerContext == null) {
            throw new IllegalStateException();
        }
        return this.certomancerContext;
    }
}
