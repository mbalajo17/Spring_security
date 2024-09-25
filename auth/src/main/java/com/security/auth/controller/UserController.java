package com.security.auth.controller;

import com.security.auth.Entity.LoginDTO;
import com.security.auth.Entity.RegisterUserDto;
import com.security.auth.Entity.User;
import com.security.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class UserController {
    @Autowired
    UserService userService;



    @PostMapping("/register")
    public User createUser(@RequestBody RegisterUserDto user ){
        return userService.createUser(user);
    }


    @PostMapping("/login")
    public String login(@RequestBody LoginDTO loginDTO ){
        return userService.loginUser(loginDTO);
    }
}

