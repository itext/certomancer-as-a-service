package com.itextpdf.test.certomancer;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThrows;

@RunWith(Parameterized.class)
public class CertomancerBadConfigTest {
    public static final String TEST_RESOURCES = "src/test/resources/badConfig";

    @Parameterized.Parameters
    public static Collection<String[]> parameters() {
        return Arrays.asList(
            new String[] {"example-response-missing-services.json", "Could not process 'services' element"},
            new String[] {"example-response-no-arch-label.json", "Invalid JSON structure"},
            new String[] {"example-response-no-certs.json", "Could not process 'cert_bundles' element"},
            new String[] {"example-response-bad-url.json", "not a valid URL"}
        );
    }

    private final String configFile;
    private final String message;

    public CertomancerBadConfigTest(String configFile, String message) {
        this.configFile = configFile;
        this.message = message;
    }


    @Test
    public void badConfigTest() {
        Throwable thrown = assertThrows(CertomancerException.class, () -> {
            Path configPath = Paths.get(TEST_RESOURCES, configFile);
            String json = String.join("\n", Files.readAllLines(configPath, StandardCharsets.UTF_8));
            CertomancerContext.fromJson(json);
        });
        String thrownMessage = thrown.getMessage();
        assertTrue(thrownMessage, thrownMessage.contains(message));
    }
}
