package com.e_gineering.salesforce.oauth;

import java.util.Objects;

public class PublicPrivateKeyPair {
  private final String publicKey;
  private final String privateKey;
  private final String privateKeyPassword;

  private PublicPrivateKeyPair(String publicKey, String privateKey, String privateKeyPassword) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.privateKeyPassword = privateKeyPassword;
  }

  public String getPublicKey() {
    return publicKey;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  public String getPrivateKeyPassword() {
    return privateKeyPassword;
  }

  public static class Builder {
    private String publicKey;
    private String privateKey;
    private String privateKeyPassword;

    public Builder publicKey(String publicKey) {
      this.publicKey = publicKey;
      return this;
    }

    public Builder privateKey(String privateKey) {
      this.privateKey = privateKey;
      return this;
    }

    public Builder privateKeyPassword(String privateKeyPassword) {
      this.privateKeyPassword = privateKeyPassword;
      return this;
    }

    public PublicPrivateKeyPair build(){
      Objects.requireNonNull(this.publicKey);
      Objects.requireNonNull(this.privateKey);
      Objects.requireNonNull(this.privateKeyPassword);
      return new PublicPrivateKeyPair(this.publicKey, this.privateKey, this.privateKeyPassword);
    }
  }
}
