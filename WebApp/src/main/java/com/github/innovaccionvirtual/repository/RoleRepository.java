package com.github.innovaccionvirtual.repository;
import java.util.Optional;

import com.github.innovaccionvirtual.models.ERole;
import com.github.innovaccionvirtual.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}