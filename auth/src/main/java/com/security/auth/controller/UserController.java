package com.security.auth.controller;

import com.security.auth.Entity.LoginDTO;
import com.security.auth.Entity.RegisterUserDto;
import com.security.auth.Entity.UpdatePassword;
import com.security.auth.Entity.User;
import com.security.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @Autowired
    private UserService userService;

    @PostMapping("/auth/register")
    public ResponseEntity<User> createUser(@RequestBody RegisterUserDto user ){
        return userService.createUser(user);
    }
    @PostMapping("/auth/login")
    public ResponseEntity<String> login(@RequestBody LoginDTO loginDTO ){
        return userService.loginUser(loginDTO);
    }


    @PutMapping("/updatePassword")
    public ResponseEntity<String> updatePassword(@RequestBody UpdatePassword updatePassword){
        return userService.updatePassWord(updatePassword);
    }
}

