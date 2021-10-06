package com.e_gineering.salesforce.oauth;

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

  private final String clientId;
  private final String clientSecret;
  private final String baseUrl;
  private final String jwtAudience;
  private final String subject;

  private final RSASSASigner signer;
  private final RSASSAVerifier signatureVerifier;

  private final HttpClient httpClient;

  private final ObjectMapper objectMapper;

  public JWTFlowOAuthService(
    String privateKey,
    String publicKey,
    String password,
    String clientId,
    String clientSecret,
    String baseUrl,
    String jwtAudience,
    String subject)
    throws CertificateException,
    NoSuchAlgorithmException,
    KeyStoreException,
    IOException,
    UnrecoverableKeyException {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.baseUrl = baseUrl;
    this.jwtAudience = jwtAudience;
    this.subject = subject;
    EnvKeyStore envKeyStore = EnvKeyStore.createFromPEMStrings(privateKey, publicKey, password);
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
      clientId,
      clientSecret
    );

    HttpRequest request = HttpRequest.newBuilder()
      .POST(HttpRequest.BodyPublishers.noBody())
      .uri(URI.create(url))
      .build();

    try {
      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

      Map<String, String> body = new ObjectMapper().readValue(response.body(), new TypeReference<>() {
      });

      return body.get("access_token");

    } catch (IOException | InterruptedException e) {
      throw new RuntimeException(e);
    }
  }

  public String generatedJWT() {

    final JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

    JWTClaimsSet claimSet = new JWTClaimsSet.Builder()
      .issuer(clientId)
      .subject(subject)
      .audience(jwtAudience)
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
