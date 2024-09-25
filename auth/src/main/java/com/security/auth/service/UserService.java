package com.security.auth.service;

import com.security.auth.Entity.LoginDTO;
import com.security.auth.Entity.RegisterUserDto;
import com.security.auth.Entity.Role;
import com.security.auth.Entity.User;
import com.security.auth.repo.RoleRepo;
import com.security.auth.repo.Userrepo;
import com.security.auth.util.JWTConfig;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class UserService {

    @Autowired
    Userrepo userrepo;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    JWTConfig jwtConfig;
    @Autowired
    RoleRepo roleRepo;

    public ResponseEntity<User> createUser(RegisterUserDto registerUserDto) {
        try {
            User user = new User();
            user.setUserName(registerUserDto.getUserName());
            user.setMail(registerUserDto.getEmail());
            user.setPassword(passwordEncoder.encode(registerUserDto.getPassword()));
            if (registerUserDto.getRole() != null && registerUserDto.getRole().getId() != null) {
                Role role = roleRepo.findById(registerUserDto.getRole().getId())
                        .orElseThrow(() -> new RuntimeException("Role not found"));
                user.setRole(role);
            }
            userrepo.save(user);
            return ResponseEntity.ok().body(user);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }


    public ResponseEntity<String> loginUser(LoginDTO loginDTO) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword(), Collections.emptyList());
        try {
            Authentication authResult = authenticationManager.authenticate(authToken);
            User userDTO = (User) authResult.getPrincipal();
            String token = generateToken(Arrays.asList(userDTO.getAuthority()), jwtConfig, userDTO);
            return ResponseEntity.ok().body(token);
        } catch (Exception exception) {
            return ResponseEntity.badRequest().body("USER NOT FOUND");
        }
    }


    public String generateToken(List authentication, JWTConfig jwtConfig, User user) {
        long currentTime = System.currentTimeMillis();
        Map<String, String> map = new HashMap<>();
        map.put("userName", user.getUsername());
        map.put("mail", user.getMail());
        map.put("authority",user.getAuthority());

        return Jwts.builder()
                .setSubject(user.getMail())
                .claim("authorities", authentication)
                .setIssuedAt(new Date(currentTime))
                .setExpiration(new Date(currentTime + jwtConfig.getJwtExpiration() * 1000L))
                .signWith(SignatureAlgorithm.HS256, jwtConfig.getSecret().getBytes())
                .setHeaderParam("users", map)
                .compact();
    }
}
