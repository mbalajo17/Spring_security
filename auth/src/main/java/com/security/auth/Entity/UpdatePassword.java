package com.security.auth.Entity;

import lombok.Data;

@Data
public class UpdatePassword {
    private String oldPassword;
    private String newPassword;
}
