package com.cloudProject.cloudP.repository;

import com.cloudProject.cloudP.entity.FileJob;
import com.cloudProject.cloudP.entity.enums.FileJobStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface FileJobRepository extends JpaRepository<FileJob, Long> {

    List<FileJob> findByUserIdOrderByCreatedAtDesc(Long userId);
    List<FileJob> findByStatusAndUpdatedAtBefore(FileJobStatus status, LocalDateTime before);

    List<FileJob> findByStatusAndCreatedAtBefore(FileJobStatus status, LocalDateTime before);

}
