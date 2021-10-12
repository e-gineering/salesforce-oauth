package com.e_gineering.salesforce.oauth;

import java.util.Objects;

public class JWTParameters {
  private final String clientId;
  private final String clientSecret;
  private final String jwtAudience;
  private final String subject;

  private JWTParameters(String clientId, String clientSecret, String jwtAudience, String subject) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.jwtAudience = jwtAudience;
    this.subject = subject;
  }

  public String getClientId() {
    return clientId;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public String getJwtAudience() {
    return jwtAudience;
  }

  public String getSubject() {
    return subject;
  }

  public static class Builder {
    private String clientId;
    private String clientSecret;
    private String jwtAudience;
    private String subject;

    public Builder clientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    public Builder clientSecret(String clientSecret) {
      this.clientSecret = clientSecret;
      return this;
    }

    public Builder jwtAudience(String jwtAudience) {
      this.jwtAudience = jwtAudience;
      return this;
    }

    public Builder subject(String subject) {
      this.subject = subject;
      return this;
    }

    public JWTParameters build(){
      Objects.requireNonNull(this.clientId);
      Objects.requireNonNull(this.clientSecret);
      Objects.requireNonNull(this.jwtAudience);
      Objects.requireNonNull(this.subject);
      return new JWTParameters(this.clientId, this.clientSecret, this.jwtAudience, this.subject);
    }
  }

}
