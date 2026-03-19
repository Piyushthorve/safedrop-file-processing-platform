package com.cloudProject.cloudP.entity;

import com.cloudProject.cloudP.entity.enums.UrlType;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "presigned_url_requests")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
public class PresignedUrlRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "file_job_id", nullable = false)
    private Long fileJobId;

    @Enumerated(EnumType.STRING)
    @Column(name = "url_type", nullable = false, length = 20)
    private UrlType urlType;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
