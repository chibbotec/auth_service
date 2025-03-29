package com.ll.authservice.domain.auth.repository;


import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.ll.authservice.domain.auth.entity.User;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);
  Optional<User> findByRefreshToken(String refreshToken);
}