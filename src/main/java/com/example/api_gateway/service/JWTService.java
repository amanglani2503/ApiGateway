package com.example.api_gateway.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JWTService {

    private static final Logger logger = LoggerFactory.getLogger(JWTService.class);

    @Value("${jwt.secret}")
    private String secretKey;

    // Generate signing key from base64-encoded secret
    private SecretKey getKey() {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(secretKey);
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (Exception e) {
            logger.error("Error decoding JWT secret key", e);
            throw new RuntimeException("Failed to decode secret key", e);
        }
    }

    // Parse and extract all claims from token
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            logger.error("Failed to extract claims from token: {}", token, e);
            throw new RuntimeException("Invalid JWT token", e);
        }
    }

    // Public method to extract claims
    public Claims extractClaims(String token) {
        return extractAllClaims(token);
    }

    // Validate token by checking signature and expiration
    public boolean validateToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            boolean isValid = claims.getExpiration().after(new Date());
            logger.debug("Token validation result for '{}': {}", token, isValid);
            return isValid;
        } catch (Exception e) {
            logger.warn("JWT validation failed for token: {}", token, e);
            return false;
        }
    }
}
