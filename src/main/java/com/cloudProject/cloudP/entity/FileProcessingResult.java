package com.cloudProject.cloudP.entity;

import com.cloudProject.cloudP.entity.enums.StorageProvider;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "file_processing_results")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
public class FileProcessingResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "file_job_id", nullable = false)
    private Long fileJobId;

    @Column(name = "result_type", nullable = false, length = 50)
    private String resultType;

    @Enumerated(EnumType.STRING)
    @Column(name = "storage_provider", nullable = false, length = 20)
    private StorageProvider storageProvider;

    @Column(name = "storage_bucket", length = 100)
    private String storageBucket;

    @Column(name = "storage_key", nullable = false, length = 500)
    private String storageKey;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
