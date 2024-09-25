package com.security.auth.Entity;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

@Entity
@Data
@Table(name = "user")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String userName;
    private String password;
    private String mail;
    private Date createDate;
    private Date expireDate;
    private Boolean isActive;
    @OneToOne(cascade = CascadeType.REFRESH,fetch = FetchType.LAZY)
    @JoinTable(name = "user_role",joinColumns = @JoinColumn(name = "user_num",referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_num"))
    private Role role;

    @Override
    public String toString() {
        return "User{" + "id=" + id + ", userName=" + userName + ", active=" + isActive + ", createdDate=" + createDate + ", expireDate=" + expireDate + '}';
    }
    @Transient
    private String authority;



    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getUsername() {
        return this.userName;
    }

    public String getAuthority() {
        return role.getRoleName();
    }

}
