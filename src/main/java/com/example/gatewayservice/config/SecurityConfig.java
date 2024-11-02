package com.example.gatewayservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.WebFilter;

import com.example.gatewayservice.filter.JwtAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final JwtAuthenticationFilter jwtAuthenticationFilter;

	@Bean
	public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
		return http
			.formLogin(ServerHttpSecurity.FormLoginSpec::disable)
			.csrf(ServerHttpSecurity.CsrfSpec::disable)
			.httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
			.authorizeExchange(exchanges -> exchanges
				.pathMatchers("/auth-service/**").permitAll()
				.pathMatchers(HttpMethod.POST, "/member-service/api/member").permitAll()
				.pathMatchers(HttpMethod.GET, "/member-service/v3/api-docs", "/auth-service/v3/api-docs", "/crewup-service/v3/api-docs").permitAll()
				.anyExchange().authenticated()
			)
			.addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
			.build();
	}
}
