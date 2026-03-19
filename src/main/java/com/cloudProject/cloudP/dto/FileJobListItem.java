package com.cloudProject.cloudP.dto;

import com.cloudProject.cloudP.entity.enums.FileJobStatus;

import java.time.LocalDateTime;

public class FileJobListItem {
    private Long id;
    private String originalFilename;
    private FileJobStatus status;
    private Long sizeBytes;
    private LocalDateTime createdAt;

    public FileJobListItem(Long id, String originalFilename, FileJobStatus status, Long sizeBytes, LocalDateTime createdAt) {
        this.id = id;
        this.originalFilename = originalFilename;
        this.status = status;
        this.sizeBytes = sizeBytes;
        this.createdAt = createdAt;
    }

    public Long getId() { return id; }
    public String getOriginalFilename() { return originalFilename; }
    public FileJobStatus getStatus() { return status; }
    public Long getSizeBytes() { return sizeBytes; }
    public LocalDateTime getCreatedAt() { return createdAt; }
}
