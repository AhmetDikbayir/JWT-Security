package com.tpe.service;

import com.tpe.domain.Role;
import com.tpe.domain.User;
import com.tpe.domain.enums.UserRole;
import com.tpe.dto.RegisterRequest;
import com.tpe.exception.ConflictException;
import com.tpe.exception.ResourceNotFoundException;
import com.tpe.repository.RoleRepository;
import com.tpe.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public void registerUser(RegisterRequest request) {

        // username unique mi ??
        if(userRepository.existsByUserName(request.getUserName())){
            throw new ConflictException("user is already registered");
        }

        Role role = roleRepository.findByName(UserRole.ROLE_STUDENT).orElseThrow(()->
                new ResourceNotFoundException("Role Not Found"));

        Set<Role> roles = new HashSet<>();
        roles.add(role);

        User user= new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setUserName(request.getUserName());
        user.setRoles(roles);
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        userRepository.save(user);

    }
}