package com.e_gineering.salesforce.oauth;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class PublicPrivateKeyPairTest {

  @ParameterizedTest
  @CsvSource(value= {
    "null, null, null",
    "null, testPrivateKeyPassword, testPublicKey",
    "testPrivateKey, null, testPublicKey",
    "testPrivateKey, testPrivateKeyPassword, null"
  }, nullValues={"null"})
  void parametersRequiredTest_(String privateKey, String password, String publicKey){
    Assertions.assertThrows(NullPointerException.class, () -> new PublicPrivateKeyPair.Builder()
      .privateKey(privateKey)
      .privateKeyPassword(password)
      .publicKey(publicKey)
      .build());
  }

  @Test
  void parametersSetTest(){
    String privateKey = "testClientId";
    String privateKeyPassword = "testClientSecret";
    String publicKey = "testJwtAudience";
    PublicPrivateKeyPair keyPair = new PublicPrivateKeyPair.Builder()
      .privateKey(privateKey)
      .privateKeyPassword(privateKeyPassword)
      .publicKey(publicKey)
      .build();

    Assertions.assertEquals(privateKey, keyPair.getPrivateKey());
    Assertions.assertEquals(privateKeyPassword, keyPair.getPrivateKeyPassword());
    Assertions.assertEquals(publicKey, keyPair.getPublicKey());
  }

}
