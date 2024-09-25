package com.security.auth.service;

import com.security.auth.Entity.*;
import com.security.auth.repo.RoleRepo;
import com.security.auth.repo.Userrepo;
import com.security.auth.util.JWTConfig;
import com.security.auth.util.JWTUtils;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class UserService {

    @Autowired
    private Userrepo userrepo;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTConfig jwtConfig;
    @Autowired
    private RoleRepo roleRepo;

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
            String token = JWTUtils.generateToken(Arrays.asList(userDTO.getAuthority()), jwtConfig, userDTO);
            return ResponseEntity.ok().body(token);
        } catch (Exception exception) {
            return ResponseEntity.badRequest().body("USER NOT FOUND");
        }
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
