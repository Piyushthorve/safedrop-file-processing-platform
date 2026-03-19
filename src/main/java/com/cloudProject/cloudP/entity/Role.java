package com.cloudProject.cloudP.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "roles")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
public class Role {

    @Id
    private Short id;   // because SMALLINT

    @Column(nullable = false, unique = true, length = 30)
    private String name; // USER / ADMIN
}
