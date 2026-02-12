package com.secure.notes.repositories;

import com.secure.notes.models.Role;
import com.secure.notes.models.enums.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(AppRole appRole);

}
