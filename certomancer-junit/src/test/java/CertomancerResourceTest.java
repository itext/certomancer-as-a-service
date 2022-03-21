import com.itextpdf.pkix.testutils.CertomancerResource;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CRLHolder;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;


public class CertomancerResourceTest {

    @ClassRule
    public static final CertomancerResource CERTOMANCER =
            new CertomancerResource("test-config.yml");

    @Test
    public void testLoadCertomancerResource() {
        String subjStr = CERTOMANCER.getContext().get("signer1").cert.getSubject().toString();
        Assert.assertTrue(subjStr.contains("Alice"));
    }

    @Test
    public void testFetchCrl() throws IOException {
        CRLDistPoint cdp =
                CRLDistPoint.fromExtensions(CERTOMANCER.getContext().get("signer1").cert.getExtensions());
        DistributionPoint dp = cdp.getDistributionPoints()[0];
        GeneralNames names = (GeneralNames) dp.getDistributionPoint().getName();
        String urlStr = DERIA5String.getInstance(names.getNames()[0].getName()).getString();
        URL url = new URL(urlStr);
        X509CRLHolder crl;
        try(InputStream is = url.openConnection().getInputStream()) {
             crl = new X509CRLHolder(is);
        }
        String issuerString = crl.getIssuer().toString();
        Assert.assertTrue(issuerString.contains("Intermediate"));
    }
}
