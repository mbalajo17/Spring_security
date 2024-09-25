package com.security.auth.Entity;

import lombok.Data;

@Data
public class LoginDTO {
    private String email;
    private String password;
}
