package com.cloudProject.cloudP.jobs;

import com.cloudProject.cloudP.entity.FileJob;
import com.cloudProject.cloudP.entity.enums.FileJobStatus;
import com.cloudProject.cloudP.repository.FileJobRepository;
import com.cloudProject.cloudP.service.FileJobService;
import com.cloudProject.cloudP.service.S3ObjectService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;

@Component
public class FileCleanupJob {

    private final FileJobRepository fileJobRepository;
    private final S3ObjectService s3ObjectService;
    private final FileJobService fileJobService;

    @Value("${cleanup.enabled:true}")
    private boolean enabled;

    @Value("${cleanup.failed-ttl-minutes:60}")
    private long failedTtlMinutes;

    @Value("${cleanup.unconfirmed-ttl-minutes:30}")
    private long unconfirmedTtlMinutes;

    public FileCleanupJob(FileJobRepository fileJobRepository,
                          S3ObjectService s3ObjectService,
                          FileJobService fileJobService) {
        this.fileJobRepository = fileJobRepository;
        this.s3ObjectService = s3ObjectService;
        this.fileJobService = fileJobService;
    }

    @Scheduled(cron = "${cleanup.cron:0 */10 * * * *}")
    public void cleanup() {
        if (!enabled) return;

        // 1) FAILED files older than TTL (use updated_at)
        LocalDateTime failedBefore = LocalDateTime.now().minusMinutes(failedTtlMinutes);
        List<FileJob> failedJobs = fileJobRepository.findByStatusAndUpdatedAtBefore(FileJobStatus.FAILED, failedBefore);

        for (FileJob job : failedJobs) {
            cleanupOne(job, "Auto-cleanup FAILED (older than " + failedTtlMinutes + " min)");
        }

        // 2) Unconfirmed PRESIGN_CREATED older than TTL (use created_at)
        LocalDateTime unconfirmedBefore = LocalDateTime.now().minusMinutes(unconfirmedTtlMinutes);
        List<FileJob> unconfirmedJobs = fileJobRepository.findByStatusAndCreatedAtBefore(FileJobStatus.PRESIGN_CREATED, unconfirmedBefore);

        for (FileJob job : unconfirmedJobs) {
            cleanupOne(job, "Auto-cleanup UNCONFIRMED (older than " + unconfirmedTtlMinutes + " min)");
        }
    }

    private void cleanupOne(FileJob job, String reason) {
        // If already deleted, skip
        if (job.getStatus() == FileJobStatus.DELETED) return;

        // delete from S3 (idempotent)
        s3ObjectService.delete(job.getStorageKey());

        // mark DB deleted
        fileJobService.markDeletedIfNotAlready(job.getId(), reason);
    }
}
