package com.e_gineering.salesforce.oauth.exceptions;

public class JWTFlowException extends RuntimeException {
  public JWTFlowException(String message, Throwable cause) {
    super(message, cause);
  }
}
