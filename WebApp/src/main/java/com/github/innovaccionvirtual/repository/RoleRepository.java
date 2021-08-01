package com.github.innovaccionvirtual.repository;

import com.github.innovaccionvirtual.models.ERole;
import com.github.innovaccionvirtual.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
