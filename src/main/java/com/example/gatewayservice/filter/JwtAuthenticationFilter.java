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
import reactor.core.publisher.Mono;

import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.example.gatewayservice.exception.JwtErrorCode;
import com.example.gatewayservice.exception.JwtException;

@Component
@Slf4j
public class JwtAuthenticationFilter implements WebFilter {

	@Value("${jwt.secret}")
	private final String secretKey;
	private final SecretKey signingKey;

	public JwtAuthenticationFilter(@Value("${jwt.secret}") String secretKey) {
		this.secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
		this.signingKey = Keys.hmacShaKeyFor(this.secretKey.getBytes());
	}


	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		String token = resolveToken(exchange.getRequest());
		if (!StringUtils.hasText(token))
			throw new JwtException(JwtErrorCode.AUTHORIZATION_HEADER_NOT_FOUND);

		validateToken(token);
		String subject = extractSubject(token);
		ServerHttpRequest request = exchange.getRequest().mutate()
			.header("X-Member-Id", subject)
			.build();

		return chain.filter(exchange.mutate().request(request).build());
	}
	
	private String extractSubject(String token) {
		return Jwts.parserBuilder()
			.setSigningKey(signingKey)
			.build()
			.parseClaimsJws(token)
			.getBody()
			.getSubject();
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
