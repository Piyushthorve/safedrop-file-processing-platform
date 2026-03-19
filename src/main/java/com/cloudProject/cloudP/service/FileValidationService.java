package com.cloudProject.cloudP.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Service
public class FileValidationService {

    private final long maxSizeBytes;
    private final Set<String> allowedContentTypes;
    private final Set<String> allowedExtensions;

    public FileValidationService(
            @Value("${file.max-size-bytes}") long maxSizeBytes,
            @Value("${file.allowed-content-types}") String allowedContentTypes,
            @Value("${file.allowed-extensions}") String allowedExtensions
    ) {
        this.maxSizeBytes = maxSizeBytes;

        this.allowedContentTypes = new HashSet<>();
        Arrays.stream(allowedContentTypes.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .forEach(this.allowedContentTypes::add);

        this.allowedExtensions = new HashSet<>();
        Arrays.stream(allowedExtensions.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .map(String::toLowerCase)
                .forEach(this.allowedExtensions::add);
    }

    public void validateUploadRequest(String fileName, String contentType, long sizeBytes) {

        // 1) size check
        if (sizeBytes <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "sizeBytes must be > 0");
        }
        if (sizeBytes > maxSizeBytes) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "File too large. Max allowed: " + maxSizeBytes + " bytes");
        }

        // 2) filename sanity
        if (fileName == null || fileName.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "fileName is required");
        }
        if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\") ) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid fileName");
        }
        if (fileName.length() > 200) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "fileName too long");
        }

        // 3) extension check
        String ext = getExtension(fileName);
        if (ext == null || !allowedExtensions.contains(ext)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "File extension not allowed: " + ext);
        }

        // 4) content-type check
        if (contentType == null || contentType.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "contentType is required");
        }
        if (!allowedContentTypes.contains(contentType)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "contentType not allowed: " + contentType);
        }
    }

    private String getExtension(String fileName) {
        int idx = fileName.lastIndexOf('.');
        if (idx < 0 || idx == fileName.length() - 1) return null;
        return fileName.substring(idx + 1).toLowerCase();
    }
}
