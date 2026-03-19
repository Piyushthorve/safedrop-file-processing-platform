package com.cloudProject.cloudP.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;

@Service
public class S3ObjectService {

    private final S3Client s3Client;

    @Value("${aws.s3.bucket}")
    private String bucket;

    public S3ObjectService(S3Client s3Client) {
        this.s3Client = s3Client;
    }

    public boolean exists(String objectKey) {
        try {
            s3Client.headObject(HeadObjectRequest.builder()
                    .bucket(bucket)
                    .key(objectKey)
                    .build());
            return true;
        } catch (NoSuchKeyException e) {
            return false;
        } catch (S3Exception e) {
            // 404 also comes as S3Exception sometimes
            if (e.statusCode() == 404) return false;
            throw e;
        }
    }

    public HeadObjectResponse head(String objectKey) {
        return s3Client.headObject(HeadObjectRequest.builder()
                .bucket(bucket)
                .key(objectKey)
                .build());
    }


    public void delete(String objectKey) {
        s3Client.deleteObject(DeleteObjectRequest.builder()
                .bucket(bucket)
                .key(objectKey)
                .build());
    }

}
