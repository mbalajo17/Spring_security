package com.security.auth.repo;

import com.security.auth.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface Userrepo extends JpaRepository<User,Long> {




    Optional<User> findByMail(String username);
}
