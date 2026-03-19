package com.cloudProject.cloudP.dto;

public class PresignUploadResponse {
    private Long fileJobId;
    private String objectKey;
    private String uploadUrl;
    private long expiresInSeconds;

    public PresignUploadResponse(Long fileJobId, String objectKey, String uploadUrl, long expiresInSeconds) {
        this.fileJobId = fileJobId;
        this.objectKey = objectKey;
        this.uploadUrl = uploadUrl;
        this.expiresInSeconds = expiresInSeconds;
    }

    public Long getFileJobId() { return fileJobId; }
    public String getObjectKey() { return objectKey; }
    public String getUploadUrl() { return uploadUrl; }
    public long getExpiresInSeconds() { return expiresInSeconds; }
}
