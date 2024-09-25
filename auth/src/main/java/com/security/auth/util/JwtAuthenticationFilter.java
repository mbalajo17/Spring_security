package com.security.auth.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.security.auth.Entity.User;
import com.security.auth.repo.Userrepo;
import io.jsonwebtoken.*;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


@Component
public class JwtAuthenticationFilter implements Filter {

    @Autowired
    private JWTConfig jwtConfig;
    private DaoAuthenticationProvider daoAuthenticationProvider;
    @Autowired
    Userrepo userrepo;


    public JwtAuthenticationFilter(DaoAuthenticationProvider authenticationManager,
                                   JWTConfig jwtConfig, Userrepo userDAO) {
        this.jwtConfig = jwtConfig;
        this.daoAuthenticationProvider = authenticationManager;
        this.userrepo = userDAO;
    }


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        String authorization = httpServletRequest.getHeader("Authorization");
        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
        String jwt = null;
        try {
            if (authorization!=null && authorization.startsWith("Bearer")) {
                jwt = authorization.replace("Bearer", "");
                jwt = jwt.replace(" ", "");
                User user = verify(jwt, httpServletRequest, httpResponse);
                if (user != null) {
                    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(token);
                }
            } else {
                filterChain.doFilter(servletRequest, servletResponse);
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    public User verify(String token, HttpServletRequest httpServletRequest, HttpServletResponse httpResponse) {
        try {
            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(jwtConfig.getSecret().getBytes())
                    .build()
                    .parseClaimsJws(token);

            ObjectMapper objectMapper = new ObjectMapper();
            User user = objectMapper.convertValue(claimsJws.getHeader().get("users"), User.class);
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
