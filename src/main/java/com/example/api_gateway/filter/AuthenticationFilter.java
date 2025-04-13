package com.example.api_gateway.filter;

import com.example.api_gateway.service.JWTService;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);

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

            // Apply filter only on secured routes
            if (validator.isSecured.test(request)) {
                logger.info("Secured route accessed: {}", request.getURI());

                // Reject if Authorization header is missing
                if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    logger.warn("Missing Authorization header for request: {}", request.getURI());
                    return unauthorizedResponse("Missing Authorization header");
                }

                // Extract and validate Bearer token
                String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    logger.warn("Invalid Authorization header format for request: {}", request.getURI());
                    return unauthorizedResponse("Invalid Authorization header");
                }

                String token = authHeader.substring(7);
                try {
                    logger.debug("Validating token for request: {}", request.getURI());
                    jwtService.validateToken(token);

                    // Extract user details from token
                    Claims claims = jwtService.extractClaims(token);
                    String role = claims.get("role", String.class);
                    String email = claims.getSubject();

                    logger.info("Token valid. User: {}, Role: {}", email, role);

                    // Modify request with user role and source info
                    ServerHttpRequest modifiedRequest = request.mutate()
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                            .header("X-User-Role", role)
                            .header("X-Source", "api-gateway")
                            .build();

                    return chain.filter(exchange.mutate().request(modifiedRequest).build());

                } catch (Exception e) {
                    logger.error("Token validation failed: {}", e.getMessage());
                    return unauthorizedResponse("Unauthorized access: " + e.getMessage());
                }
            }

            // Allow request if route is not secured
            logger.debug("Unsecured route accessed: {}", request.getURI());
            return chain.filter(exchange);
        };
    }

    // Throw exception for unauthorized access
    private Mono<Void> unauthorizedResponse(String message) {
        logger.error("Unauthorized response: {}", message);
        throw new RuntimeException(message);
    }

    // Required config class for filter factory
    public static class Config {
    }
}
