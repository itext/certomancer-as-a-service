package com.itextpdf.pkix.testutils;

import com.itextpdf.test.certomancer.CertomancerConfigManager;
import com.itextpdf.test.certomancer.CertomancerContext;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.rules.ExternalResource;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class CertomancerResource extends ExternalResource {
    public static final CertomancerConfigManager CERTOMANCER_CONFIG_MANAGER = loadConfigManager();
    public static final String CERTOMANCER_CONFIG_URL = "http://localhost:9000/config";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static CertomancerConfigManager loadConfigManager() {
        try {
            return new CertomancerConfigManager(new URL(CERTOMANCER_CONFIG_URL));
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private final String configResourceName;
    private CertomancerContext certomancerContext = null;

    public CertomancerResource(String configResourceName) {
        this.configResourceName = configResourceName;
    }

    protected void before() throws IOException {
        InputStream is = CertomancerResource.class.getClassLoader()
                .getResourceAsStream("certomancer/" + this.configResourceName);
        if(is == null) {
            throw new FileNotFoundException();
        }
        // Java 9+, but eh
        String yamlConfig = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        this.certomancerContext = CERTOMANCER_CONFIG_MANAGER.submitConfiguration(yamlConfig);
    }

    public CertomancerContext getContext() {
        if(this.certomancerContext == null) {
            throw new IllegalStateException();
        }
        return this.certomancerContext;
    }
}
