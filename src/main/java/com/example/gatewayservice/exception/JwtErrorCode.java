package com.example.gatewayservice.exception;

import lombok.Getter;

@Getter
public enum JwtErrorCode {
	INVALID_JWT_SIGNATURE("Invalid JWT signature"),
	INVALID_JWT_TOKEN("Invalid JWT token"),
	EXPIRED_JWT_TOKEN("Expired JWT token"),
	UNSUPPORTED_JWT_TOKEN("Unsupported JWT token"),
	JWT_CLAIMS_EMPTY("JWT claims string is empty"),
	JWT_CLAIMS_INVALID("JWT claims string is invalid"),
	AUTHORIZATION_HEADER_NOT_FOUND("Authorization header not found")
	;

	private final String message;

	JwtErrorCode(String message) {
		this.message = message;
	}
}
