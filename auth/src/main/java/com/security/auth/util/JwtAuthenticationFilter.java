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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import java.io.IOException;

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
                User user =JWTUtils.verify(jwt, httpServletRequest, httpResponse,jwtConfig);
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


}
