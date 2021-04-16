package com.itextpdf.test.certomancer;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.Assert.*;

public class CertomancerContextTest {

    public static final String TEST_RESOURCES = "src/test/resources/goodConfig";

    // not actually used to make requests, just to compare with test data
    public static final String CERTOMANCER_URL = "http://localhost:9000";

    @Test
    public void serviceParseTest1() throws IOException {
        Path configPath = Paths.get(TEST_RESOURCES, "example-response.json");
        String json = String.join("\n", Files.readAllLines(configPath, StandardCharsets.UTF_8));
        CertomancerContext context = CertomancerContext.fromJson(json);

        assertEquals(1, context.getOCSPResponders().values().size());
        assertEquals(1, context.getCRLRepositories().values().size());
        assertEquals(0, context.getTimeStampingServices().values().size());
        assertEquals(0, context.getCertificateRepositories().values().size());
        assertEquals(0, context.getPluginEndpoints().values().size());

        String ocspUrl = context.getOCSPResponders().get("interm").toString();
        assertTrue(ocspUrl.startsWith(CERTOMANCER_URL));
        assertTrue(ocspUrl.endsWith("ocsp/interm"));
    }


    @Test
    public void serviceParseTest2() throws IOException {
        Path configPath = Paths.get(TEST_RESOURCES, "example-response2.json");
        String json = String.join("\n", Files.readAllLines(configPath, StandardCharsets.UTF_8));
        CertomancerContext context = CertomancerContext.fromJson(json);

        assertEquals(1, context.getOCSPResponders().values().size());
        assertEquals(1, context.getCRLRepositories().values().size());
        assertEquals(1, context.getTimeStampingServices().values().size());
        assertEquals(0, context.getCertificateRepositories().values().size());
        assertEquals(0, context.getPluginEndpoints().values().size());
    }

    @Test
    public void serviceParseTest3() throws IOException {
        Path configPath = Paths.get(TEST_RESOURCES, "example-response-no-services.json");
        String json = String.join("\n", Files.readAllLines(configPath, StandardCharsets.UTF_8));
        CertomancerContext context = CertomancerContext.fromJson(json);

        assertEquals(0, context.getOCSPResponders().values().size());
        assertEquals(0, context.getCRLRepositories().values().size());
        assertEquals(0, context.getTimeStampingServices().values().size());
        assertEquals(0, context.getCertificateRepositories().values().size());
        assertEquals(0, context.getPluginEndpoints().values().size());
    }

    @Test
    public void certParseTest1() throws IOException, GeneralSecurityException {

        Path configPath = Paths.get(TEST_RESOURCES, "example-response.json");
        String json = String.join("\n", Files.readAllLines(configPath, StandardCharsets.UTF_8));
        CertomancerContext context = CertomancerContext.fromJson(json);

        CertomancerContext.CertPackage signer1 = context.get("signer1");
        assertEquals(new X500Name("C=BE,O=Testing Authority,OU=Signers,CN=Alice"), signer1.cert.getSubject());
        CertomancerContext.CertPackage signer2 = context.get("signer2");
        assertEquals(new X500Name("C=BE,O=Testing Authority,OU=Signers,CN=Bob"), signer2.cert.getSubject());


        // compare DER-encoding of certs
        assertArrayEquals(signer1.cert.getEncoded(), signer1.getJCACert().getEncoded());
        assertEquals(2, signer1.otherCerts.size());
        List<X509Certificate> jcaOtherCerts = signer1.getJCAOtherCerts();
        assertArrayEquals(signer1.otherCerts.get(0).getEncoded(), jcaOtherCerts.get(0).getEncoded());
        assertArrayEquals(signer1.otherCerts.get(1).getEncoded(), jcaOtherCerts.get(1).getEncoded());

        // make a signature (just to test the key processing logic)
        PrivateKey pk = signer1.getJCAPrivateKey();
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(pk);
        byte[] dataToSign = "test".getBytes(StandardCharsets.UTF_8);
        sig.update(dataToSign);
        byte[] signature = sig.sign();

        sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(signer1.getJCACert());
        sig.update(dataToSign);
        assertTrue(sig.verify(signature));
    }
}
