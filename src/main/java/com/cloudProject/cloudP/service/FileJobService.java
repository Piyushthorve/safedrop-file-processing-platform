package com.cloudProject.cloudP.service;

import com.cloudProject.cloudP.entity.FileJob;
import com.cloudProject.cloudP.entity.PresignedUrlRequest;
import com.cloudProject.cloudP.entity.enums.FileJobStatus;
import com.cloudProject.cloudP.entity.enums.StorageProvider;
import com.cloudProject.cloudP.entity.enums.UrlType;
import com.cloudProject.cloudP.repository.FileJobRepository;
import com.cloudProject.cloudP.repository.PresignedUrlRequestRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;


import java.time.LocalDateTime;

@Service
public class FileJobService {

    private final FileJobRepository fileJobRepository;
    private final PresignedUrlRequestRepository presignedUrlRequestRepository;

    @Value("${aws.s3.bucket}")
    private String bucket;

    @Value("${aws.s3.presign.expiry-seconds:300}")
    private long expirySeconds;

    public FileJobService(FileJobRepository fileJobRepository,
                          PresignedUrlRequestRepository presignedUrlRequestRepository) {
        this.fileJobRepository = fileJobRepository;
        this.presignedUrlRequestRepository = presignedUrlRequestRepository;
    }

    @Transactional
    public FileJob createUploadJob(Long userId,
                                   String originalFilename,
                                   String contentType,
                                   Long sizeBytes,
                                   String storageKey) {

        FileJob job = FileJob.builder()
                .userId(userId)
                .originalFilename(originalFilename)
                .contentType(contentType)
                .sizeBytes(sizeBytes)
                .status(FileJobStatus.PRESIGN_CREATED)
                .storageProvider(StorageProvider.S3)
                .storageBucket(bucket)
                .storageKey(storageKey)
                .errorMessage(null)
                .build();

        job = fileJobRepository.save(job);

        PresignedUrlRequest req = PresignedUrlRequest.builder()
                .fileJobId(job.getId())
                .urlType(UrlType.UPLOAD)
                .expiresAt(LocalDateTime.now().plusSeconds(expirySeconds))
                .build();

        presignedUrlRequestRepository.save(req);

        return job;
    }

    @Transactional
    public FileJob markUploaded(Long fileJobId, Long sizeBytes, String contentType) {
        FileJob job = fileJobRepository.findById(fileJobId)
                .orElseThrow(() -> new RuntimeException("File job not found: " + fileJobId));

        // ✅ NEW: allow confirm only once
        if (job.getStatus() != FileJobStatus.PRESIGN_CREATED) {
            throw new IllegalStateException("Cannot confirm upload. Current status: " + job.getStatus());
        }

        job.setStatus(FileJobStatus.UPLOADED);
        job.setSizeBytes(sizeBytes);

        if (contentType != null && !contentType.isBlank()) {
            job.setContentType(contentType);
        }

        return fileJobRepository.save(job);
    }

    @Transactional
    public void logDownloadPresign(Long fileJobId) {
        presignedUrlRequestRepository.save(
                PresignedUrlRequest.builder()
                        .fileJobId(fileJobId)
                        .urlType(UrlType.DOWNLOAD)
                        .expiresAt(LocalDateTime.now().plusSeconds(expirySeconds))
                        .build()
        );
    }

    @Transactional
    public FileJob markDeleted(Long fileJobId) {
        FileJob job = fileJobRepository.findById(fileJobId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "File job not found"));

        // If already deleted, just return (idempotent)
        if (job.getStatus() == FileJobStatus.DELETED) {
            return job;
        }

        job.setStatus(FileJobStatus.DELETED);
        return fileJobRepository.save(job);
    }

    @Transactional
    public FileJob validateAndGetForReupload(Long fileJobId, Long userId) {

        FileJob job = fileJobRepository.findById(fileJobId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "File job not found"));

        // ownership
        if (!job.getUserId().equals(userId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You cannot access this file");
        }

        // state rule
        if (job.getStatus() != FileJobStatus.PRESIGN_CREATED) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Reupload not allowed in status: " + job.getStatus()
            );
        }

        return job;
    }

    @Transactional
    public void logUploadPresign(Long fileJobId) {
        presignedUrlRequestRepository.save(
                PresignedUrlRequest.builder()
                        .fileJobId(fileJobId)
                        .urlType(UrlType.UPLOAD)
                        .expiresAt(LocalDateTime.now().plusSeconds(expirySeconds))
                        .build()
        );
    }

    @Transactional
    public void markFailed(Long fileJobId, String reason) {

        FileJob job = fileJobRepository.findById(fileJobId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "File job not found"));

        job.setStatus(FileJobStatus.FAILED);
        job.setErrorMessage(reason);

        fileJobRepository.save(job);
    }

    @Transactional
    public void markDeletedIfNotAlready(Long fileJobId, String reason) {
        FileJob job = fileJobRepository.findById(fileJobId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "File job not found"));

        if (job.getStatus() == FileJobStatus.DELETED) return;

        job.setStatus(FileJobStatus.DELETED);
        job.setErrorMessage(reason);
        fileJobRepository.save(job);
    }

    @Transactional
    public FileJob markProcessing(Long fileJobId) {
        FileJob job = fileJobRepository.findById(fileJobId)
                .orElseThrow(() -> new RuntimeException("File job not found: " + fileJobId));

        if (job.getStatus() != FileJobStatus.UPLOADED) {
            throw new IllegalStateException("Cannot mark PROCESSING. Current status: " + job.getStatus());
        }

        job.setStatus(FileJobStatus.PROCESSING);
        return fileJobRepository.save(job);
    }








}
