package com.itextpdf.test.certomancer;

import java.io.IOException;

public class CertomancerException extends IOException  {

    private static String fmtMsg(String label, String message) {
        return String.format("%s (Certomancer arch '%s')", message, label == null ? "<unknown>" : label);
    }
    public CertomancerException(String label, String message) {
        super(fmtMsg(label, message));
    }

    public CertomancerException(String label, String msg, Throwable cause) {
        super(fmtMsg(label, msg), cause);
    }
}
