package com.security.auth.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.security.auth.Entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class JWTUtils {

    public static String generateToken(List authentication, JWTConfig jwtConfig, User user) {
        long currentTime = System.currentTimeMillis();
        Map<String, String> map = new HashMap<>();
        map.put("userName", user.getUsername());
        map.put("mail", user.getMail());
        map.put("authority",user.getAuthority());
        map.put("id", String.valueOf(user.getId()));

        return Jwts.builder()
                .subject(user.getMail())
                .claim("authorities", authentication)
                .issuedAt(new Date(currentTime))
                .expiration(new Date(currentTime + jwtConfig.getJwtExpiration() * 1000L))
                .signWith(Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8)))
                .claim("users",map)
                .compact();
    }

    public static User verify(String token, HttpServletRequest httpServletRequest, HttpServletResponse httpResponse, JWTConfig jwtConfig) {
        try {
            Claims claimsJws = Jwts.parser()
                    .verifyWith(Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            ObjectMapper objectMapper = new ObjectMapper();
            User user = objectMapper.convertValue(claimsJws.get("users"), User.class);
            user.setPassword(token);
            return user;
        } catch (Exception e) {
            String message = "Invalid Token";
            httpServletRequest.setAttribute("expiredMsg", message);
            httpServletRequest.setAttribute("expiredStatus", 401);
            sendError(httpResponse, message, 401);
            return null;
        }
    }

    private static void sendError(HttpServletResponse response, String message, int status) {
        Map<String, String> error = new HashMap<>();
        error.put("error", "Unauthorized");
        error.put("message", message);
        error.put("path", "/auth");
        error.put("status", String.valueOf(status));

        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        Gson g = new Gson();
        try {
            response.getOutputStream().write(g.toJson(error).getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
