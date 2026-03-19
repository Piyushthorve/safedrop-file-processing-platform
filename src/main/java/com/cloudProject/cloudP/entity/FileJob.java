package com.cloudProject.cloudP.entity;

import com.cloudProject.cloudP.entity.enums.FileJobStatus;
import com.cloudProject.cloudP.entity.enums.StorageProvider;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "file_jobs")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
public class FileJob {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // keep as Long because table has user_id bigint (you can map relation later)
    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "original_filename", nullable = false, length = 255)
    private String originalFilename;

    @Column(name = "content_type", length = 100)
    private String contentType;

    @Column(name = "size_bytes")
    private Long sizeBytes;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private FileJobStatus status;

    @Enumerated(EnumType.STRING)
    @Column(name = "storage_provider", nullable = false, length = 20)
    private StorageProvider storageProvider;

    @Column(name = "storage_bucket", length = 100)
    private String storageBucket;

    @Column(name = "storage_key", nullable = false, length = 500)
    private String storageKey;

    @Column(name = "error_message", length = 500)
    private String errorMessage;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
