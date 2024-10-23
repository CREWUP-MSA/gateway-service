package com.example.gatewayservice.filter;

import java.util.Base64;

import javax.crypto.SecretKey;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.web.server.ServerWebExchange;

import com.example.gatewayservice.exception.JwtErrorCode;
import com.example.gatewayservice.exception.JwtException;

@Component
@Slf4j
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

	@Value("${jwt.secret}")
	private final String secretKey;
	private final SecretKey signingKey;

	public JwtAuthenticationFilter(@Value("${jwt.secret}") String secretKey) {
		super(Config.class);
		this.secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
		this.signingKey = Keys.hmacShaKeyFor(this.secretKey.getBytes());
	}

	public static class Config { }

	@Override
	public GatewayFilter apply(Config config) {
		return (exchange, chain) -> {

			if (isExcludedPathAndMethod(exchange))
				return chain.filter(exchange);

			String token = resolveToken(exchange.getRequest());
			if (!StringUtils.hasText(token))
				throw new JwtException(JwtErrorCode.AUTHORIZATION_HEADER_NOT_FOUND);

			validateToken(token);
			String subject = extractSubject(token);
			ServerHttpRequest request = exchange.getRequest().mutate()
				.header("X-Member-Id", subject)
				.build();

			return chain.filter(exchange.mutate().request(request).build());
		};
	}

	private String extractSubject(String token) {
		return Jwts.parserBuilder()
			.setSigningKey(signingKey)
			.build()
			.parseClaimsJws(token)
			.getBody()
			.getSubject();
	}

	/**
	 * Jwt 검증 제외 경로 및 메소드
	 * 회원가입, swagger-ui 접근은 Jwt 검증 제외
	 * @param exchange ServerWebExchange
	 * @return boolean 검증 제외 여부
 	 */
	private boolean isExcludedPathAndMethod(ServerWebExchange exchange) {
		String path = exchange.getRequest().getPath().toString();
		String method = exchange.getRequest().getMethod().toString();

		return (path.equals("/member-service/api/member") && method.equals("POST")) ||
			(path.startsWith("/member-service/swagger-ui") && method.equals("GET")) ||
			(path.startsWith("/auth-service/swagger-ui") && method.equals("GET")) ||
			(path.startsWith("/crewup-service/swagger-ui") && method.equals("GET")) ||
			(path.startsWith("/member-service/v3/api-docs") && method.equals("GET")) ||
			(path.startsWith("/auth-service/v3/api-docs") && method.equals("GET")) ||
			(path.startsWith("/crewup-service/v3/api-docs") && method.equals("GET"));
	}

	private void validateToken(String token) {
		try {
			Jwts.parserBuilder()
				.setSigningKey(signingKey)
				.build()
				.parseClaimsJws(token);
		} catch (SecurityException e) {
			log.error("validateToken: Invalid JWT signature");
			throw new JwtException(JwtErrorCode.INVALID_JWT_SIGNATURE);
		} catch (ExpiredJwtException e) {
			log.error("validateToken: Expired JWT token");
			throw new JwtException(JwtErrorCode.EXPIRED_JWT_TOKEN);
		} catch (MalformedJwtException e) {
			log.error("validateToken: Invalid JWT token");
			throw new JwtException(JwtErrorCode.INVALID_JWT_TOKEN);
		} catch (UnsupportedJwtException e) {
			log.error("validateToken: Unsupported JWT token");
			throw new JwtException(JwtErrorCode.UNSUPPORTED_JWT_TOKEN);
		} catch (IllegalArgumentException e) {
			log.error("validateToken: JWT claims string is empty");
			throw new JwtException(JwtErrorCode.JWT_CLAIMS_EMPTY);
		}
	}



	private String resolveToken(ServerHttpRequest request) {
		String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

		if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer "))
			return bearerToken.substring(7);
		else {
			log.error("resolveToken: Invalid or expired JWT token");
			throw new JwtException(JwtErrorCode.INVALID_JWT_TOKEN);
		}
	}

}
