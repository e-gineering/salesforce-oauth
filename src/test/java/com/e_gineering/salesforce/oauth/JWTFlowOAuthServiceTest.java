package com.e_gineering.salesforce.oauth;

import com.e_gineering.salesforce.oauth.exceptions.JWTFlowException;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class JWTFlowOAuthServiceTest {

  private final String baseUrl = "http://test";
  private PublicPrivateKeyPair keyPair;
  private JWTParameters defaultJWTParameters;
  @Mock
  private HttpClient client;

  @BeforeEach
  public void setUp() throws GeneralSecurityException, IOException, OperatorCreationException {
    KeyPair kp = KeyPairUtils.generateKeyPair();
    String privateKey = KeyPairUtils.privateKeyAsString(kp.getPrivate());
    String cert = KeyPairUtils.generateCertificateAsString(kp);
    this.keyPair = new PublicPrivateKeyPair.Builder()
      .publicKey(cert)
      .privateKey(privateKey)
      .privateKeyPassword("")
      .build();
    this.defaultJWTParameters = new JWTParameters.Builder()
      .clientId("clientId")
      .clientSecret("clientSecret")
      .jwtAudience("jwtAudience")
      .subject("subject")
      .build();
  }

  @SuppressWarnings("unchecked")
  @Test
  void requestAccessToken() throws IOException, InterruptedException {
    JWTFlowOAuthService service = createService(defaultJWTParameters);
    ArgumentCaptor<HttpRequest> requestArgumentCaptor = ArgumentCaptor.forClass(HttpRequest.class);
    HttpResponse<String> mockedResponse = mock(HttpResponse.class);
    when(mockedResponse.body()).thenReturn("{\"access_token\": \"test token\"}");
    when(client.send(requestArgumentCaptor.capture(), any(HttpResponse.BodyHandlers.ofString().getClass())))
      .thenReturn(mockedResponse);

    String accessToken = service.requestAccessToken();

    Assertions.assertEquals("test token", accessToken);
    HttpRequest actual = requestArgumentCaptor.getValue();
    Assertions.assertEquals("POST", actual.method());
    Assertions.assertEquals("http", actual.uri().getScheme());
    Assertions.assertEquals("test", actual.uri().getHost());
    Assertions.assertEquals("/services/oauth2/token", actual.uri().getPath());

    String expectedGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    String jwt = service.generatedJWT();

    String expectedQuery = String.format("grant_type=%s&assertion=%s&client_id=%s&client_secret=%s", expectedGrantType, jwt, defaultJWTParameters.getClientId(), defaultJWTParameters.getClientSecret());
    Assertions.assertEquals(expectedQuery, actual.uri().getQuery());
  }

  @Test
  void generatedJWT() {
    JWTFlowOAuthService service = createService(defaultJWTParameters);

    String jwt = service.generatedJWT();

    Assertions.assertNotNull(jwt);
  }

  @Test
  void validateJWT() {
    JWTFlowOAuthService service = createService(defaultJWTParameters);

    String token = service.generatedJWT();

    boolean validated = service.validateJWT(token);

    Assertions.assertTrue(validated);
  }

  @Test
  void validateJWT_InvalidFormat() {
    JWTFlowOAuthService service = createService(defaultJWTParameters);

    assertThrows(JWTFlowException.class, () -> service.validateJWT("invalid token"));
  }

  @Test
  void validateJWT_Invalid_TokenSignedWithOther() throws GeneralSecurityException, IOException, OperatorCreationException {
    KeyPair kp = KeyPairUtils.generateKeyPair();
    String privateKey = KeyPairUtils.privateKeyAsString(kp.getPrivate());
    String cert = KeyPairUtils.generateCertificateAsString(kp);
    PublicPrivateKeyPair keyPair = new PublicPrivateKeyPair.Builder()
      .publicKey(cert)
      .privateKey(privateKey)
      .privateKeyPassword("")
      .build();

    String tokenSignedWithOther = new JWTFlowOAuthService.Builder()
      .baseUrl(baseUrl)
      .jwtParameters(new JWTParameters.Builder()
        .clientId("otherClientId")
        .clientSecret("otherClientSecret")
        .jwtAudience("otherJwtAudience")
        .subject("otherSubject")
        .build())
      .createSignerAndVerifierWithKeyPair(keyPair)
      .httpClient(client)
      .build().generatedJWT();

    JWTFlowOAuthService service = createService(defaultJWTParameters);

    boolean validated = service.validateJWT(tokenSignedWithOther);

    Assertions.assertFalse(validated);
  }

  private JWTFlowOAuthService createService(JWTParameters jwtParameters) {
    return new JWTFlowOAuthService.Builder()
      .baseUrl(baseUrl)
      .jwtParameters(jwtParameters)
      .createSignerAndVerifierWithKeyPair(keyPair)
      .httpClient(client)
      .build();
  }
}
