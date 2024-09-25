package com.security.auth.util;


import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Data
public class JWTConfig {
    @Value("${security.jwt.secret}")
    private String secret;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;
}
