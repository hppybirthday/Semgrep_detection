package com.example.bigdata.log;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;

@SpringBootApplication
public class LogProcessingApplication {
    public static void main(String[] args) {
        SpringApplication.run(LogProcessingApplication.class, args);
    }
}

@RestController
@RequestMapping("/logs")
class LogController {
    private final LogService logService;

    public LogController(LogService logService) {
        this.logService = logService;
    }

    @GetMapping("/{filename}")
    public String getLog(@PathVariable String filename) {
        return logService.processLog(filename);
    }
}

class LogService {
    private final LogRepository logRepository;

    public LogService(LogRepository logRepository) {
        this.logRepository = logRepository;
    }

    public String processLog(String filename) {
        // 漏洞点：直接拼接用户输入的文件名
        Path logPath = Paths.get("/var/log/bigdata/", filename);
        
        if (!Files.exists(logPath)) {
            return "Log file not found";
        }
        
        return logRepository.readLogFile(logPath.toString());
    }
}

class LogRepository {
    public String readLogFile(String filePath) {
        try {
            File file = new File(filePath);
            byte[] fileContent = Files.readAllBytes(file.toPath());
            return new String(fileContent);
        } catch (Exception e) {
            return "Error reading file: " + e.getMessage();
        }
    }
}

// 域名实体类
record LogFile(String name, String content) {}
