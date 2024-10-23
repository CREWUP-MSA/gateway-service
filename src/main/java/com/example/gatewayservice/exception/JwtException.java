package com.example.gatewayservice.exception;

public class JwtException extends RuntimeException {

	private final JwtErrorCode errorCode;

	public JwtException(JwtErrorCode errorCode) {
		super(errorCode.getMessage());
		this.errorCode = errorCode;
	}
}
