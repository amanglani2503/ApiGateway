package com.example.api_gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouteValidator {

    private static final Logger logger = LoggerFactory.getLogger(RouteValidator.class);

    // Publicly accessible endpoints (no authentication required)
    private static final List<String> openApiEndpoints = List.of(
            "/auth/register",
            "/auth/login"
    );

    // Predicate to check if a request targets a secured endpoint
    public Predicate<ServerHttpRequest> isSecured = request -> {
        String path = request.getURI().getPath();
        boolean isSecuredPath = openApiEndpoints.stream().noneMatch(uri -> path.equalsIgnoreCase(uri));
        logger.debug("Evaluating route security: Path='{}', Secured={}", path, isSecuredPath);
        return isSecuredPath;
    };
}
