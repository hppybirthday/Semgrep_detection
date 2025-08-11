package com.example.bigdata;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.io.*;
import java.net.*;
import com.fasterxml.jackson.databind.*;

@Component
class LogFetcher {
    private final ObjectMapper objectMapper = new ObjectMapper();

    public CheckPermissionInfo fetchLog(String logId) throws Exception {
        String executorAddress = "http://log-server:8080/logs/" + logId;
        HttpURLConnection connection = (HttpURLConnection) new URL(executorAddress).openConnection();
        connection.setRequestMethod("GET");
        
        if (connection.getResponseCode() != 200) {
            throw new RuntimeException("Failed to fetch log");
        }
        
        try (InputStream responseStream = connection.getInputStream()) {
            return objectMapper.readValue(responseStream, CheckPermissionInfo.class);
        }
    }
}

@RestController
@RequestMapping("/api/logs")
public class LogController {
    private final LogFetcher logFetcher;

    public LogController(LogFetcher logFetcher) {
        this.logFetcher = logFetcher;
    }

    @GetMapping("/{logId}")
    public CheckPermissionInfo getLog(@PathVariable String logId) throws Exception {
        return logFetcher.fetchLog(logId);
    }
}

record CheckPermissionInfo(String permissionLevel, String dataAccessScope) {}

// 模拟启动类
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}