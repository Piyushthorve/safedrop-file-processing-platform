package com.cloudProject.cloudP.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvocationType;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;

import java.util.HashMap;
import java.util.Map;

@Service
public class PiiLambdaInvokeService {

    private final LambdaClient lambdaClient;
    private final ObjectMapper objectMapper;

    @Value("${aws.lambda.pii.function-name}")
    private String functionName;

    @Value("${aws.s3.bucket}")
    private String bucketName;

    @Value("${aws.lambda.invoke-async:true}")
    private boolean invokeAsync;

    public PiiLambdaInvokeService(LambdaClient lambdaClient, ObjectMapper objectMapper) {
        this.lambdaClient = lambdaClient;
        this.objectMapper = objectMapper;
    }

    public void invokePiiProcessor(Long fileJobId, String storageKey) {
        try {
            Map<String, Object> payload = new HashMap<>();
            payload.put("fileJobId", fileJobId);
            payload.put("bucket", bucketName);
            payload.put("key", storageKey);

            String json = objectMapper.writeValueAsString(payload);

            InvokeRequest req = InvokeRequest.builder()
                    .functionName(functionName)
                    .invocationType(invokeAsync ? InvocationType.EVENT : InvocationType.REQUEST_RESPONSE)
                    .payload(SdkBytes.fromUtf8String(json))
                    .build();

            lambdaClient.invoke(req);

        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke PII Lambda: " + e.getMessage(), e);
        }
    }
}
