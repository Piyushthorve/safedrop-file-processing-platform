package com.cloudProject.cloudP.controller;

import com.cloudProject.cloudP.dto.MeResponse;
import com.cloudProject.cloudP.dto.RegisterRequest;
import com.cloudProject.cloudP.entity.User;
import com.cloudProject.cloudP.repository.RoleRepository;
import com.cloudProject.cloudP.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import com.cloudProject.cloudP.dto.LoginRequest;
import com.cloudProject.cloudP.dto.AuthResponse;
import com.cloudProject.cloudP.security.JwtService;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;


import java.util.Set;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;


    @PostMapping("/register")
    public String register(@Valid @RequestBody RegisterRequest req) {

        if (userRepository.existsByEmail(req.getEmail())) {
            throw new IllegalStateException("Email already registered");
        }


        var userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("USER role missing in roles table"));

        User u = User.builder()
                .email(req.getEmail())
                .username(req.getUsername())
                .fullName(req.getFullName())
                .phone(req.getPhone())
                .password(passwordEncoder.encode(req.getPassword()))
                .enabled(true)
                .accountNonLocked(true)
                .roles(Set.of(userRole))
                .build();

        userRepository.save(u);

        return "Registered successfully";
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest req) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
        );

        String token = jwtService.generateToken(req.getEmail());
        return new AuthResponse(token);
    }

    @GetMapping("/me")
    public MeResponse me() {

        var auth = org.springframework.security.core.context.SecurityContextHolder
                .getContext()
                .getAuthentication();

        String email = auth.getName();

        var roles = auth.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .collect(java.util.stream.Collectors.toSet());

        return new MeResponse(email, roles);
    }

}
