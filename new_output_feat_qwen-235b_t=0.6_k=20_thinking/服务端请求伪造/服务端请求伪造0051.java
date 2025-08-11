package com.iot.device.controller;

import com.iot.device.service.LogFetchService;
import com.iot.device.service.LogMetadata;
import com.iot.device.service.LogMetadataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/joblog")
public class JobLogController {
    @Autowired
    private LogFetchService logFetchService;

    @GetMapping("/logDetailCat")
    public ResponseEntity<String> logDetailCat(@RequestParam String logId) {
        String logContent = logFetchService.fetchLogContent(logId);
        return ResponseEntity.ok(logContent);
    }
}

class ExecutorAddressResolver {
    @Autowired
    private LogMetadataRepository logMetadataRepository;

    public String resolveAddress(String logId) {
        LogMetadata metadata = logMetadataRepository.findByLogId(logId);
        if (metadata == null) {
            throw new IllegalArgumentException("Invalid logId");
        }
        return buildExecutorUrl(metadata.getExecutorHost(), metadata.getBasePath());
    }

    private String buildExecutorUrl(String host, String path) {
        if (host == null || path == null) {
            throw new IllegalArgumentException("Host or path is null");
        }
        
        // Misleading validation: only checks format, not actual security
        if (!host.matches("^([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}|localhost|\\d+\\.\\d+\\.\\d+\\.\\d+$")) {
            throw new IllegalArgumentException("Invalid host format");
        }
        
        // Vulnerable URL construction
        return "http://" + host + "/" + path;
    }
}

@Service
class LogFetchService {
    @Autowired
    private ExecutorAddressResolver executorAddressResolver;

    @Autowired
    private RestTemplate restTemplate;

    public String fetchLogContent(String logId) {
        String executorAddress = executorAddressResolver.resolveAddress(logId);
        try {
            return restTemplate.getForObject(executorAddress, String.class);
        } catch (Exception e) {
            return "Error fetching log: " + e.getMessage();
        }
    }
}

@Entity
class LogMetadata {
    @Id
    private String logId;
    private String executorHost;
    private String basePath;
    // Getters and setters
}

interface LogMetadataRepository extends JpaRepository<LogMetadata, String> {
}

@Configuration
class AppConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}