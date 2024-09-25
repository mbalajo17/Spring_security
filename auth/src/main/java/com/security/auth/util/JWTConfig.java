package com.security.auth.util;

import com.security.auth.Entity.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@Data
public class JWTConfig {


    @Value("${security.jwt.secret}")
    private String secret;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;
}
