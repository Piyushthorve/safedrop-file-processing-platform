package com.cloudProject.cloudP.dto;

import jakarta.validation.constraints.NotNull;

public class ConfirmUploadRequest {

    @NotNull
    private Long fileJobId;

    public Long getFileJobId() { return fileJobId; }
    public void setFileJobId(Long fileJobId) { this.fileJobId = fileJobId; }
}
