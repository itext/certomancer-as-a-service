package com.itextpdf.test.certomancer;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class CertomancerContext {

    private static final JcaX509CertificateConverter CERT_CONVERTER = new JcaX509CertificateConverter();
    private static final JcaPEMKeyConverter KEY_CONVERTER = new JcaPEMKeyConverter();

    public static class CertPackage {
        public final X509CertificateHolder cert;
        public final PrivateKeyInfo pk;
        public final List<X509CertificateHolder> otherCerts;

        public CertPackage(X509CertificateHolder cert, PrivateKeyInfo pk, List<X509CertificateHolder> otherCerts) {
            this.cert = cert;
            this.pk = pk;
            this.otherCerts = otherCerts;
        }

        public X509Certificate getJCACert() throws CertificateException {
            return CERT_CONVERTER.getCertificate(this.cert);
        }

        public PrivateKey getJCAPrivateKey() throws PEMException {
            return KEY_CONVERTER.getPrivateKey(this.pk);
        }

        public List<X509Certificate> getJCAOtherCerts() throws CertificateException {
            List<X509Certificate> result = new ArrayList<>(this.otherCerts.size());
            for(X509CertificateHolder cert : this.otherCerts) {
                result.add(CERT_CONVERTER.getCertificate(cert));
            }
            return result;
        }
    }

    public enum ServiceType {OCSP, TIME_STAMPING, CRL_REPO, CERT_REPO, PLUGIN}

    public final String label;
    public final Map<String, CertPackage> certBundles;
    private final Map<ServiceType, Map<String, URL>> services;

    public CertomancerContext(String label, Map<String, CertPackage> certBundles,
                              Map<ServiceType, Map<String, URL>> services) {
        this.label = label;
        this.certBundles = Collections.unmodifiableMap(certBundles);
        this.services = services;
    }

    private static <K, V> Map<K, V> guardMap(Map<K, V> original) {
        if(original == null) {
            return Collections.emptyMap();
        } else {
            return Collections.unmodifiableMap(original);
        }
    }

    public Map<String, URL> getTimeStampingServices() {
        return guardMap(this.services.get(ServiceType.TIME_STAMPING));
    }

    public Map<String, URL> getOCSPResponders() {
        return guardMap(this.services.get(ServiceType.OCSP));
    }

    public Map<String, URL> getCRLRepositories() {
        return guardMap(this.services.get(ServiceType.CRL_REPO));
    }

    public Map<String, URL> getCertificateRepositories() {
        return guardMap(this.services.get(ServiceType.CERT_REPO));
    }

    public Map<String, URL> getPluginEndpoints() {
        return guardMap(this.services.get(ServiceType.PLUGIN));
    }

    public static CertomancerContext fromJson(String json) throws CertomancerException {

        // yes, I know this is an antipattern. I don't care.
        // When doing this "for real", adding a JSON schema with proper typing would be a lot better.
        final JsonObject root;
        final String archLabel;
        try {
            root = JsonParser.parseString(json).getAsJsonObject();
            archLabel = Optional.ofNullable(root.get("arch_label")).orElseThrow().getAsString();
        } catch (IllegalStateException | NoSuchElementException ex) {
            throw new CertomancerException(null, "Invalid JSON structure");
        }
        final JsonObject certBundles;
        try {
            certBundles = Optional.ofNullable(root.get("cert_bundles")).orElseThrow().getAsJsonObject();
        } catch(NoSuchElementException ex) {
            throw new CertomancerException(archLabel, "Could not process 'cert_bundles' element");
        }
        Map<String, CertPackage> parsedBundles = parseCertBundles(archLabel, certBundles);

        final JsonObject serviceDict;
        try {
            serviceDict = Optional.ofNullable(root.get("services")).orElseThrow().getAsJsonObject();
        } catch(NoSuchElementException ex) {
            throw new CertomancerException(archLabel, "Could not process 'services' element");
        }
        Map<ServiceType, Map<String, URL>> services = parseServices(archLabel, serviceDict);

        return new CertomancerContext(archLabel, parsedBundles, services);
    }

    private static Map<ServiceType, Map<String, URL>> parseServices(String archLabel, JsonObject serviceDict)
            throws CertomancerException {
        Map<ServiceType, Map<String, URL>> services = new HashMap<>();
        for(Map.Entry<String, JsonElement> e: serviceDict.entrySet()) {
            final ServiceType type;
            try {
                type = ServiceType.valueOf(e.getKey().toUpperCase(Locale.ROOT));
            } catch(IllegalArgumentException ignored) {
                continue;  // ignore unknown service types
            }

            Map<String, URL> servicesOfType = new HashMap<>();
            for(Map.Entry<String, JsonElement> svcEntry: e.getValue().getAsJsonObject().entrySet()) {
                JsonElement urlValue = svcEntry.getValue();
                try {
                    servicesOfType.put(svcEntry.getKey(), new URL(urlValue.getAsString()));
                } catch(IllegalStateException | MalformedURLException ex) {
                    String msg = String.format("%s is not a valid URL", urlValue.toString());
                    throw new CertomancerException(archLabel, msg, ex);
                }
            }

            services.put(type, servicesOfType);
        }

        return services;
    }

    private static Map<String, CertPackage> parseCertBundles(String archLabel, JsonObject certBundles)
            throws CertomancerException {

        Map<String, X509CertificateHolder> certs = new HashMap<>();

        Base64.Decoder decoder = Base64.getDecoder();

        // collect certs first
        // TODO I'd prefer streams, but do those play nicely with maps?
        try {
            for(Map.Entry<String, JsonElement> e: certBundles.entrySet()) {
                String certLabel = e.getKey();
                final JsonObject certBundle = e.getValue().getAsJsonObject();
                final String certB64 = Optional.ofNullable(certBundle.get("cert")).orElseThrow().getAsString();
                certs.put(certLabel, new X509CertificateHolder(decoder.decode(certB64)));
            }
        } catch(IllegalArgumentException | IOException ex) {
            throw new CertomancerException(archLabel, "Error in certificate collection", ex);
        }

        // next, we do another pass to collect keys & other certs
        Map<String, CertPackage> parsedBundles = new HashMap<>();
        try {
            for(Map.Entry<String, JsonElement> e: certBundles.entrySet()) {
                String certLabel = e.getKey();
                final JsonObject certBundle = e.getValue().getAsJsonObject();

                X509CertificateHolder cert = certs.get(certLabel);

                final JsonArray otherCertLabels = Optional.ofNullable(certBundle.get("other_certs"))
                        .orElseThrow().getAsJsonArray();

                // otherCertLabels is a JSON array of certificate labels
                // so we need to gather the actual X509Certificate objects from the certs map we built before.
                List<X509CertificateHolder> others = StreamSupport.stream(otherCertLabels.spliterator(), false)
                        .map(JsonElement::getAsString).map(lbl -> {
                            X509CertificateHolder c = certs.get(lbl);
                            if(c == null) {
                                throw new NoSuchElementException("Other cert '" + lbl + "' does not exist");
                            }
                            return c;
                        }).collect(Collectors.toList());


                // parse private key info
                final Optional<PrivateKeyInfo> keyInfo = Optional.ofNullable(certBundle.get("key"))
                        .map(JsonElement::getAsString).map(decoder::decode).map(PrivateKeyInfo::getInstance);

                parsedBundles.put(certLabel, new CertPackage(cert, keyInfo.orElse(null), others));
            }
        } catch(IllegalArgumentException ex) {
            throw new CertomancerException(archLabel, "Error in certificate bundle processing", ex);
        }
        return parsedBundles;
    }
}
