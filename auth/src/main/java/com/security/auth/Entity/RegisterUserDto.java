package com.security.auth.Entity;

import lombok.Data;

@Data
public class RegisterUserDto {
    private String email;
    private String password;
    private String userName;
    private Role role;
}
