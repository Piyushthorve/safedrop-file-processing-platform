package com.cloudProject.cloudP.dto;

public class PresignDownloadResponse {
    private Long fileJobId;
    private String downloadUrl;
    private long expiresInSeconds;

    public PresignDownloadResponse(Long fileJobId, String downloadUrl, long expiresInSeconds) {
        this.fileJobId = fileJobId;
        this.downloadUrl = downloadUrl;
        this.expiresInSeconds = expiresInSeconds;
    }

    public Long getFileJobId() { return fileJobId; }
    public String getDownloadUrl() { return downloadUrl; }
    public long getExpiresInSeconds() { return expiresInSeconds; }
}
