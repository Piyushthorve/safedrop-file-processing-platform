package com.cloudProject.cloudP.repository;

import com.cloudProject.cloudP.entity.PresignedUrlRequest;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PresignedUrlRequestRepository extends JpaRepository<PresignedUrlRequest, Long> {
}
