package com.example.gatewayservice.filter;

import java.util.Base64;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.web.server.ServerWebExchange;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

	private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

	@Value("${jwt.secret}")
	private final String secretKey;
	private final SecretKey signingKey;

	public JwtAuthenticationFilter(@Value("${jwt.secret}") String secretKey) {
		super(Config.class);
		this.secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
		this.signingKey = Keys.hmacShaKeyFor(this.secretKey.getBytes());
	}

	public static class Config {
	}

	@Override
	public GatewayFilter apply(Config config) {
		return (exchange, chain) -> {
			/*
			  회원 가입 API 는 인증 필터를 거치지 않도록 예외 처리
			 */
			if (isExcludedPathAndMethod(exchange))
				return chain.filter(exchange);


			String token = resolveToken(exchange.getRequest());
			if (StringUtils.hasText(token))
				validateToken(token);

			return chain.filter(exchange);
		};
	}

	private boolean isExcludedPathAndMethod(ServerWebExchange exchange) {
		String path = exchange.getRequest().getPath().toString();
		String method = exchange.getRequest().getMethod().toString();

		return path.equals("/member-service/api/member") && method.equals("POST");
	}

	private void validateToken(String token) {
		try {
			Jwts.parserBuilder()
				.setSigningKey(signingKey)
				.build()
				.parseClaimsJws(token);
		}catch (JwtException | IllegalArgumentException e) {
			log.info("validateToken: Invalid or expired JWT token");
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired JWT token");
		}
	}


	private String resolveToken(ServerHttpRequest request) {
		String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

		if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer "))
			return bearerToken.substring(7);
		else {
			log.info("resolveToken: Invalid or expired JWT token");
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired JWT token");
		}
	}
}
