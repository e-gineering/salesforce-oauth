package com.e_gineering.salesforce.oauth;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class JWTParametersTest {

  @ParameterizedTest
  @CsvSource(value= {
    "null, null, null, null",
    "null, testClientSecret, testJwtAudience, testSubject",
    "testClientId, null, testJwtAudience, testSubject",
    "testClientId, testClientSecret, null, testSubject",
    "testClientId, testClientSecret, testJwtAudience, null"
  }, nullValues={"null"})
  void parametersRequiredTest_(String clientId, String clientSecret, String jwtAudience, String subject){
    Assertions.assertThrows(NullPointerException.class, () -> new JWTParameters.Builder()
      .clientId(clientId)
      .clientSecret(clientSecret)
      .jwtAudience(jwtAudience)
      .subject(subject)
      .build());
  }

  @Test
  void parametersSetTest(){
    String clientId = "testClientId";
    String clientSecret = "testClientSecret";
    String jwtAudience = "testJwtAudience";
    String subject = "testSubject";
    JWTParameters parameters = new JWTParameters.Builder()
      .clientId(clientId)
      .clientSecret(clientSecret)
      .jwtAudience(jwtAudience)
      .subject(subject)
      .build();

    Assertions.assertEquals(clientId, parameters.getClientId());
    Assertions.assertEquals(clientSecret, parameters.getClientSecret());
    Assertions.assertEquals(jwtAudience, parameters.getJwtAudience());
    Assertions.assertEquals(subject, parameters.getSubject());
  }
}
