package com.e_gineering.salesforce.oauth;

/*-
 * #%L
 * salesforce-oauth
 * %%
 * Copyright (C) 2021 E-gineering, Inc.
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.heroku.sdk.EnvKeyStore;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

public class JWTFlowOAuthService {
  private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
  private static final Logger log = LoggerFactory.getLogger(JWTFlowOAuthService.class);

  private final String baseUrl;
  private final JWTParameters jwtParameters;

  private final RSASSASigner signer;
  private final RSASSAVerifier signatureVerifier;

  private final HttpClient httpClient;

  private final ObjectMapper objectMapper;

  public JWTFlowOAuthService(
    String baseUrl,
    JWTParameters jwtParameters,
    PublicPrivateKeyPair keyPair)
    throws CertificateException,
    NoSuchAlgorithmException,
    KeyStoreException,
    IOException,
    UnrecoverableKeyException {
    this.baseUrl = baseUrl;
    this.jwtParameters = jwtParameters;
    EnvKeyStore envKeyStore = EnvKeyStore.createFromPEMStrings(keyPair.getPrivateKey(), keyPair.getPublicKey(), keyPair.getPrivateKeyPassword());
    final Key key = envKeyStore.keyStore().getKey("alias", envKeyStore.password().toCharArray());
    this.signer = new RSASSASigner((PrivateKey) key);
    this.signatureVerifier = new RSASSAVerifier((RSAPublicKey) envKeyStore.keyStore().getCertificate("alias").getPublicKey());

    this.objectMapper = new ObjectMapper();

    this.httpClient = HttpClient.newHttpClient();
  }

  public String requestAccessToken() {
    log.info("Requesting access token.");
    String url
      = String.format(
      baseUrl + "/services/oauth2/token?grant_type=%s&assertion=%s&client_id=%s&client_secret=%s",
      GRANT_TYPE,
      generatedJWT(),
      jwtParameters.getClientId(),
      jwtParameters.getClientSecret()
    );

    HttpRequest request = HttpRequest.newBuilder()
      .POST(HttpRequest.BodyPublishers.noBody())
      .uri(URI.create(url))
      .build();

    try {
      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

      Map<String, String> body = objectMapper.readValue(response.body(), new TypeReference<>() {
      });

      return body.get("access_token");

    } catch (IOException | InterruptedException e) {
      throw new RuntimeException(e);
    }
  }

  public String generatedJWT() {

    final JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

    JWTClaimsSet claimSet = new JWTClaimsSet.Builder()
      .issuer(jwtParameters.getClientId())
      .subject(jwtParameters.getSubject())
      .audience(jwtParameters.getJwtAudience())
      .expirationTime(getExpirationTime())
      .build();

    SignedJWT signedJWT = new SignedJWT(header, claimSet);

    try {
      signedJWT.sign(signer);
    } catch (JOSEException e) {
      throw new RuntimeException(e);
    }

    return signedJWT.serialize();
  }

  public boolean validateJWT(String token) throws ParseException, JOSEException {
    SignedJWT jwt = SignedJWT.parse(token);
    return jwt.verify(signatureVerifier);
  }

  private Date getExpirationTime() {
    final Instant now = Instant.now();
    final Instant exp = now.plus(Duration.ofMillis(2));
    return Date.from(exp);
  }

}
