package com.cloudProject.cloudP.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Set;

@Getter
@AllArgsConstructor
public class MeResponse {
    private String email;
    private Set<String> roles;
}
