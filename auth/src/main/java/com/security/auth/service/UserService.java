package com.security.auth.service;

import com.security.auth.Entity.*;
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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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
        map.put("id", String.valueOf(user.getId()));

        return Jwts.builder()
                .setSubject(user.getMail())
                .claim("authorities", authentication)
                .setIssuedAt(new Date(currentTime))
                .setExpiration(new Date(currentTime + jwtConfig.getJwtExpiration() * 1000L))
                .signWith(SignatureAlgorithm.HS256, jwtConfig.getSecret().getBytes())
                .setHeaderParam("users", map)
                .compact();
    }

    public ResponseEntity<String> updatePassWord(UpdatePassword updatePassword) {
        try {
            User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            User user1 = userrepo.findById(user.getId()).get();
            BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
            if (bCryptPasswordEncoder.matches(updatePassword.getNewPassword(), user1.getPassword())) {
                return new ResponseEntity<>("Your new password cannot be same as current password!!!", HttpStatus.PRECONDITION_FAILED);
            }
            if (Objects.nonNull(updatePassword.getNewPassword())) {
                user1.setPassword(bCryptPasswordEncoder.encode(updatePassword.getNewPassword()));
                userrepo.save(user1);
                return new ResponseEntity<>("success full update", HttpStatus.OK);
            } else {
                return new ResponseEntity<>(HttpStatus.BAD_GATEWAY);
            }

        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }
}
