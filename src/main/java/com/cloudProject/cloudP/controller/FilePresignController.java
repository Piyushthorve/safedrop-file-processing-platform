package com.cloudProject.cloudP.controller;

import com.cloudProject.cloudP.dto.ConfirmUploadRequest;
import com.cloudProject.cloudP.dto.PresignDownloadResponse;
import com.cloudProject.cloudP.dto.PresignUploadRequest;
import com.cloudProject.cloudP.dto.PresignUploadResponse;
import com.cloudProject.cloudP.dto.FileJobListItem;
import com.cloudProject.cloudP.entity.FileJob;
import com.cloudProject.cloudP.entity.User;
import com.cloudProject.cloudP.entity.enums.FileJobStatus;
import com.cloudProject.cloudP.repository.FileJobRepository;
import com.cloudProject.cloudP.repository.UserRepository;
import com.cloudProject.cloudP.service.*;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import java.util.List;


@RestController
@RequestMapping("/files")
public class FilePresignController {

    private final FileJobRepository fileJobRepository;
    private final S3PresignService presignService;
    private final S3ObjectService s3ObjectService;
    private final FileJobService fileJobService;
    private final UserRepository userRepository;
    private final FileValidationService fileValidationService;
    private final PiiLambdaInvokeService piiLambdaInvokeService;


    public FilePresignController(
            S3PresignService presignService,
            S3ObjectService s3ObjectService,
            FileJobService fileJobService,
            UserRepository userRepository,
            FileJobRepository fileJobRepository,
            FileValidationService fileValidationService,
            PiiLambdaInvokeService piiLambdaInvokeService
    ) {
        this.presignService = presignService;
        this.s3ObjectService = s3ObjectService;
        this.fileJobService = fileJobService;
        this.userRepository = userRepository;
        this.fileJobRepository = fileJobRepository;
        this.fileValidationService = fileValidationService;
        this.piiLambdaInvokeService = piiLambdaInvokeService;
    }

    @PostMapping("/upload-url")
    public PresignUploadResponse createUploadUrl(@Valid @RequestBody PresignUploadRequest req) {

        fileValidationService.validateUploadRequest(
                req.getFileName(),
                req.getContentType(),
                req.getSizeBytes()
        );


        // 1) get logged-in email from SecurityContext (your JWT subject is email)
        String email = SecurityContextHolder.getContext().getAuthentication().getName();

        // 2) fetch userId
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found for email: " + email));

        // 3) generate presigned URL + object key
        var result = presignService.presignPut(user.getId(), req.getFileName(), req.getContentType());


        // 4) create DB job + log presigned url request
        var job = fileJobService.createUploadJob(
                user.getId(),
                req.getFileName(),
                req.getContentType(),
                req.getSizeBytes(),   // ← store expected size
                result.objectKey()
        );

        // 5) return response
        return new PresignUploadResponse(
                job.getId(),
                result.objectKey(),
                result.url(),
                presignService.getExpirySeconds()
        );
    }

    @PostMapping("/confirm-upload")
    public String confirmUpload(@Valid @RequestBody ConfirmUploadRequest req) {

        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        FileJob job = fileJobRepository.findById(req.getFileJobId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "File job not found"));

        // ownership
        if (!job.getUserId().equals(user.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You cannot access this file");
        }

        // state check
        if (job.getStatus() != FileJobStatus.PRESIGN_CREATED) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Confirm not allowed in status: " + job.getStatus()
            );
        }

        // HEAD S3 (real metadata)
        var head = s3ObjectService.head(job.getStorageKey());

        // ===== VALIDATION AGAINST REALITY =====

        // size validation
        if (job.getSizeBytes() != null && !job.getSizeBytes().equals(head.contentLength())) {
            fileJobService.markFailed(
                    job.getId(),
                    "Size mismatch. Expected=" + job.getSizeBytes() + ", Actual=" + head.contentLength()
            );
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Uploaded file size mismatch");
        }

        // content-type validation
        if (job.getContentType() != null && head.contentType() != null &&
                !job.getContentType().equals(head.contentType())) {
            fileJobService.markFailed(
                    job.getId(),
                    "ContentType mismatch. Expected=" + job.getContentType() + ", Actual=" + head.contentType()
            );
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Uploaded file type mismatch");
        }

        // ===== VALIDATION PASSED =====
        fileJobService.markUploaded(job.getId(), head.contentLength(), head.contentType());
        // NEW: mark as processing + invoke lambda
        fileJobService.markProcessing(job.getId());
        piiLambdaInvokeService.invokePiiProcessor(job.getId(), job.getStorageKey());


        return "CONFIRMED";
    }


    @GetMapping("/{fileJobId}/download-url")
    public PresignDownloadResponse createDownloadUrl(
            @PathVariable Long fileJobId,
            @RequestParam(name = "variant", required = false, defaultValue = "ORIGINAL") String variant
    ) {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found for email: " + email));

        FileJob job = fileJobRepository.findById(fileJobId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "File job not found"));

        // ownership
        if (!job.getUserId().equals(user.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You cannot access this file");
        }

        // Do not allow download if deleted
        if (job.getStatus() == FileJobStatus.DELETED) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "File is deleted");
        }

        String v = variant == null ? "ORIGINAL" : variant.trim().toUpperCase();

        String objectKey;
        if ("ORIGINAL".equals(v)) {
            // old behavior: only allow when uploaded
            if (job.getStatus() != FileJobStatus.UPLOADED &&
                    job.getStatus() != FileJobStatus.PROCESSING &&
                    job.getStatus() != FileJobStatus.PROCESSED_CLEAN &&
                    job.getStatus() != FileJobStatus.PROCESSED_PII_FOUND) {
                throw new ResponseStatusException(
                        HttpStatus.CONFLICT,
                        "Original file not ready for download. Status: " + job.getStatus()
                );
            }
            objectKey = job.getStorageKey();

        } else if ("REDACTED".equals(v)) {
            objectKey = buildRedactedKey(job);      // processed/{userId}/..._REDACTED.ext
            if (!s3ObjectService.exists(objectKey)) {
                throw new ResponseStatusException(
                        HttpStatus.CONFLICT,
                        "Redacted file not ready yet. Processing may still be running."
                );
            }

        } else if ("REPORT".equals(v)) {
            objectKey = buildReportKey(job);        // processed/{userId}/....pii-report.json
            if (!s3ObjectService.exists(objectKey)) {
                throw new ResponseStatusException(
                        HttpStatus.CONFLICT,
                        "PII report not ready yet. Processing may still be running."
                );
            }

        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Invalid variant. Use ORIGINAL, REDACTED, or REPORT");
        }

        var presigned = presignService.presignGet(objectKey);
        fileJobService.logDownloadPresign(fileJobId);

        return new PresignDownloadResponse(fileJobId, presigned.url(), presignService.getExpirySeconds());
    }

    /** processed/{userId}/{filename}.pii-report.json */
    private String buildReportKey(FileJob job) {
        String processedPrefix = getProcessedPrefix(); // processed/
        String fileName = fileNameOnly(job.getStorageKey());
        return processedPrefix + job.getUserId() + "/" + fileName + ".pii-report.json";
    }

    /** processed/{userId}/{filenameBase}_REDACTED{ext} */
    private String buildRedactedKey(FileJob job) {
        String processedPrefix = getProcessedPrefix(); // processed/
        String fileName = fileNameOnly(job.getStorageKey());

        int dot = fileName.lastIndexOf('.');
        String redactedName;
        if (dot > 0) {
            redactedName = fileName.substring(0, dot) + "_REDACTED" + fileName.substring(dot);
        } else {
            redactedName = fileName + "_REDACTED";
        }

        return processedPrefix + job.getUserId() + "/" + redactedName;
    }

    @Value("${aws.s3.processed-prefix:processed/}")
    private String processedPrefix;

    private String getProcessedPrefix() {
        if (processedPrefix == null || processedPrefix.isBlank()) return "processed/";
        return processedPrefix.endsWith("/") ? processedPrefix : processedPrefix + "/";
    }

    private String fileNameOnly(String key) {
        if (key == null) return "unknown";
        int idx = key.lastIndexOf('/');
        return (idx >= 0 && idx < key.length() - 1) ? key.substring(idx + 1) : key;
    }


    @DeleteMapping("/{fileJobId}")
    public String deleteFile(@PathVariable Long fileJobId) {

        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found for email: " + email));

        FileJob job = fileJobRepository.findById(fileJobId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "File job not found"));

        // ownership
        if (!job.getUserId().equals(user.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You cannot access this file");
        }

        // if already deleted -> idempotent
        if (job.getStatus() == FileJobStatus.DELETED) {
            return "DELETED";
        }

        // delete from S3 using DB key
        s3ObjectService.delete(job.getStorageKey());

        // mark DB deleted
        fileJobService.markDeleted(fileJobId);

        return "DELETED";
    }



    @GetMapping
    public List<FileJobListItem> listMyFiles() {

        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found for email: " + email));

        return fileJobRepository.findByUserIdOrderByCreatedAtDesc(user.getId())
                .stream()
                .map(j -> new FileJobListItem(
                        j.getId(),
                        j.getOriginalFilename(),
                        j.getStatus(),
                        j.getSizeBytes(),
                        j.getCreatedAt()
                ))
                .toList();
    }

    @PostMapping("/{fileJobId}/reupload-url")
    public PresignUploadResponse reissueUploadUrl(@PathVariable Long fileJobId) {

        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // validate job
        FileJob job = fileJobService.validateAndGetForReupload(fileJobId, user.getId());

        // generate new presigned PUT for SAME key
        var presigned = presignService.presignPutExistingKey(
                job.getStorageKey(),
                job.getContentType()
        );

        // log presign request
        fileJobService.logUploadPresign(fileJobId);

        return new PresignUploadResponse(
                job.getId(),
                job.getStorageKey(),
                presigned.url(),
                presignService.getExpirySeconds()
        );
    }







}
