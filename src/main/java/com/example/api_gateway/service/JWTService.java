//package com.example.api_gateway.service;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.io.Decoders;
//import io.jsonwebtoken.security.Keys;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.stereotype.Service;
//
//import javax.crypto.SecretKey;
//import java.util.Date;
//import java.util.function.Function;
//
//@Service
//public class JWTService {
//    @Value("${jwt.secret}")
//    private String secretKey;
//
//    public String extractRole(String token) {
//        return extractAllClaims(token).get("role", String.class);
//    }
//
//    private Claims extractAllClaims(String token) {
//        return Jwts.parser()
//                .verifyWith(getKey())
//                .build()
//                .parseSignedClaims(token)
//                .getPayload();
//    }
//
//    private SecretKey getKey() {
//        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
//        return Keys.hmacShaKeyFor(keyBytes);
//    }
//
//    public String extractUsername(String token) {
//        return extractClaim(token, Claims::getSubject);
//    }
//
//    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
//        Claims claims = extractAllClaims(token);
//        return claimResolver.apply(claims);
//    }
//
//    public boolean validateToken(String token, UserDetails userDetails) {
//        final String userName = extractUsername(token);
//        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
//    }
//
//    private boolean isTokenExpired(String token) {
//        return extractExpiration(token).before(new Date());
//    }
//
//    private Date extractExpiration(String token) {
//        return extractClaim(token, Claims::getExpiration);
//    }
//}

package com.example.api_gateway.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JWTService {

    @Value("${jwt.secret}")
    private String secretKey;

    // ✅ Decode and get the signing key
    private SecretKey getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // ✅ Extract all claims
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // ✅ Public method to get claims
    public Claims extractClaims(String token) {
        return extractAllClaims(token);
    }

    // ✅ Validate the token (used in the filter)
    public boolean validateToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return claims.getExpiration().after(new Date()); // token not expired
        } catch (Exception e) {
            return false;
        }
    }
}
