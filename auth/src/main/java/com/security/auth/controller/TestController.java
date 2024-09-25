package com.security.auth.controller;

import com.security.auth.Entity.User;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/test")
    public String testAPi(){
        User userDTO = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        return "success JWT";
    }
}
