package com.cloudProject.cloudP.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;

import java.time.Duration;
import java.util.UUID;

@Service
public class S3PresignService {

    private final S3Presigner presigner;

    @Value("${aws.s3.bucket}")
    private String bucket;

    @Value("${aws.s3.presign.expiry-seconds:300}")
    private long expirySeconds;

    public S3PresignService(S3Presigner presigner) {
        this.presigner = presigner;
    }

    public PresignedPutResult presignPut(Long userId, String fileName, String contentType) {
        // basic filename safety (very small for now; we’ll harden later)
        String safeName = fileName.replace("\\", "_").replace("/", "_");

        String objectKey = "uploads/" + userId + "/" + UUID.randomUUID() + "-" + safeName;

        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(bucket)
                .key(objectKey)
                .contentType(contentType)
                .build();

        PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
                .signatureDuration(Duration.ofSeconds(expirySeconds))
                .putObjectRequest(putObjectRequest)
                .build();

        PresignedPutObjectRequest presigned = presigner.presignPutObject(presignRequest);

        return new PresignedPutResult(objectKey, presigned.url().toString());
    }

    public PresignedPutResult presignGet(String objectKey) {

        GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                .bucket(bucket)
                .key(objectKey)
                .build();

        GetObjectPresignRequest presignRequest = GetObjectPresignRequest.builder()
                .signatureDuration(Duration.ofSeconds(expirySeconds))
                .getObjectRequest(getObjectRequest)
                .build();

        PresignedGetObjectRequest presigned = presigner.presignGetObject(presignRequest);

        return new PresignedPutResult(objectKey, presigned.url().toString());
    }

    public PresignedPutResult presignPutExistingKey(String objectKey, String contentType) {

        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(bucket)
                .key(objectKey)
                .contentType(contentType)
                .build();

        PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
                .signatureDuration(Duration.ofSeconds(expirySeconds))
                .putObjectRequest(putObjectRequest)
                .build();

        PresignedPutObjectRequest presigned = presigner.presignPutObject(presignRequest);

        return new PresignedPutResult(objectKey, presigned.url().toString());
    }



    public long getExpirySeconds() {
        return expirySeconds;
    }
}
