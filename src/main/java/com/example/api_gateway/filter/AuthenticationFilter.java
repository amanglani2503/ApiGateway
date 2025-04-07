package com.example.api_gateway.filter;

import com.example.api_gateway.service.JWTService;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouteValidator validator;

    @Autowired
    private JWTService jwtService;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (validator.isSecured.test(request)) {
                if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    return unauthorizedResponse("Missing Authorization header");
                }

                String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    return unauthorizedResponse("Invalid Authorization header");
                }

                String token = authHeader.substring(7);
                try {
                    jwtService.validateToken(token);

                    // ✅ Extract claims
                    Claims claims = jwtService.extractClaims(token);
                    String role = claims.get(   "role", String.class);
                    String email = claims.getSubject();

                    // ✅ Print role for debugging
                    System.out.println("✅ API Gateway Authenticated Role: " + role + ", User: " + email);

                    // ✅ Add extra headers: role & flag that request passed through gateway
                    ServerHttpRequest modifiedRequest = request.mutate()
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                            .header("X-User-Role", role)
                            .header("X-Source", "api-gateway") // Custom header
                            .build();

                    return chain.filter(exchange.mutate().request(modifiedRequest).build());

                } catch (Exception e) {
                    return unauthorizedResponse("Unauthorized access: " + e.getMessage());
                }
            }

            return chain.filter(exchange);
        };
    }

    private Mono<Void> unauthorizedResponse(String message) {
        throw new RuntimeException(message);
    }

    public static class Config {
    }
}