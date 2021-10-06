package com.e_gineering.salesforce.oauth;

import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertTrue;

class JWTFlowOAuthServiceIT {

  @Test
  void requestAccessToken() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, ParseException, JOSEException {

    String privateKey = new String(Base64.getDecoder().decode(System.getProperty("salesforce.jwt.rsa.private-key")));
    String publicKey = new String(Base64.getDecoder().decode(System.getProperty("salesforce.jwt.rsa.public-key")));
    String password = System.getProperty("salesforce.jwt.rsa.password");
    String clientId = System.getProperty("salesforce.api.client-id");
    String clientSecret = System.getProperty("salesforce.api.client-secret");
    String baseUrl = System.getProperty("salesforce.api.base-url");
    String jwtAudience = System.getProperty("salesforce.jwt.audience");
    String subject = System.getProperty("salesforce.jwt.subject");
    var jwtFlowOAuthService = new JWTFlowOAuthService(privateKey, publicKey, password, clientId, clientSecret, baseUrl, jwtAudience, subject);

    final String jwt = jwtFlowOAuthService.generatedJWT();
    assertTrue(jwtFlowOAuthService.validateJWT(jwt));
  }
}
