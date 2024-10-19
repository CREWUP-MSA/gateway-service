package com.example.gatewayservice.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class GlobalLoggingFilter implements GlobalFilter, Ordered {

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		log.info("Request Method - {}, URL - {}", exchange.getRequest().getMethod(), exchange.getRequest().getURI());

		long startTime = System.currentTimeMillis();

		return chain.filter(exchange).then(Mono.fromRunnable(() -> {
			long endTime = System.currentTimeMillis() - startTime;
			log.info("Response URL - {}, Status Code - {}, Elapsed Time - {}ms",exchange.getRequest().getURI(), exchange.getResponse().getStatusCode(), endTime);
		}));
	}

	@Override
	public int getOrder() {
		return -1;
	}
}
