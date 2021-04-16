package com.itextpdf.test.certomancer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class CertomancerConfigManager {
    private final URL submitUrl;

    public CertomancerConfigManager(URL submitUrl) {
        this.submitUrl = submitUrl;
    }

    public CertomancerContext submitConfigurationFromFile(String configFile) throws IOException {
        String yamlConfig = new String(Files.readAllBytes(Paths.get(configFile)), StandardCharsets.UTF_8);
        return submitConfiguration(yamlConfig);
    }

    public CertomancerContext submitConfiguration(String yamlConfig) throws IOException {

        // POST the config to the Certomancer configuration endpoint, to spin up an ad-hoc PKI architecture
        HttpURLConnection conn = (HttpURLConnection) submitUrl.openConnection();
        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-yaml");
        conn.setRequestProperty("Content-Length", String.valueOf(yamlConfig.length()));

        OutputStream os = conn.getOutputStream();
        os.write(yamlConfig.getBytes());
        os.flush();
        os.close();

        // Retrieve the response
        InputStream response = conn.getInputStream();
        // Werkzeug is nice and always writes Content-Length
        byte[] respBytes = new byte[conn.getContentLength()];
        int totalRead = 0;
        int bytesRead = 0;
        do {
            totalRead += bytesRead;
            bytesRead = response.read(respBytes, totalRead,respBytes.length - totalRead);
        } while(bytesRead != -1 && totalRead < respBytes.length);

        String respString = new String(respBytes, StandardCharsets.UTF_8);

        // parse and store the response
        return CertomancerContext.fromJson(respString);
    }
}
