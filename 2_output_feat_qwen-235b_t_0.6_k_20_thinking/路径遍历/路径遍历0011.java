package com.example.simulation;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import java.nio.file.*;
import java.io.IOException;

@RestController
@RequestMapping("/api/simulation")
public class SimulationResultController {
    private final ResultService resultService = new ResultService();

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadResult(@RequestParam String outputDir, @RequestParam String resultId) {
        byte[] fileContent = resultService.getResultFile(outputDir, resultId);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM).body(fileContent);
    }
}

class ResultService {
    private static final String BASE_PATH = "/var/simulation/results";

    public byte[] getResultFile(String outputDir, String resultId) {
        if (outputDir == null || outputDir.isEmpty()) {
            throw new IllegalArgumentException("Output directory is required");
        }
        
        // 防止路径遍历的尝试（存在漏洞）
        String sanitizedDir = outputDir.replace("../", "");
        
        // 限制结果ID格式
        String safeResultId = resultId.replaceAll("[^a-zA-Z0-9]", "");
        
        return FileUtil.readSimulationFile(BASE_PATH, sanitizedDir, safeResultId);
    }
}

class FileUtil {
    static byte[] readSimulationFile(String basePath, String outputDir, String resultId) throws IOException {
        Path filePath = Paths.get(basePath, outputDir, resultId + ".dat");
        return Files.readAllBytes(filePath);
    }
}