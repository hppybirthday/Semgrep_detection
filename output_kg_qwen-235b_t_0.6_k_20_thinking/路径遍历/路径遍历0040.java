package com.example.bigdata;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;

@RestController
@RequestMapping("/api/data")
public class DataProcessor {
    private static final String DATA_ROOT = "/var/datawarehouse/";
    
    // 声明式配置：通过配置文件注入路径（模拟实际场景）
    @Value("${data.storage.root}")
    private String storageRoot = DATA_ROOT;

    /**
     * 路径遍历漏洞示例：大数据文件访问接口
     * 攻击者可通过../../构造任意文件访问
     */
    @GetMapping("/file/{filename}")
    public String readFile(@PathVariable String filename) {
        try {
            // 漏洞点：直接拼接用户输入
            Path filePath = Paths.get(storageRoot, filename);
            
            // 模拟大数据处理：读取并统计文件行数
            List<String> lines = Files.readAllLines(filePath);
            return String.format("File: %s\
Lines: %d\
Sample: %s", 
                filename, lines.size(), lines.stream().findFirst().orElse("Empty"));
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * 路径遍历漏洞示例：批量数据导入接口
     * 攻击者可通过路径遍历覆盖任意文件
     */
    @PostMapping("/import/{targetPath}")
    public String importData(@PathVariable String targetPath, @RequestBody String content) {
        try {
            // 漏洞点：用户控制的目标路径未校验
            Path outputPath = Paths.get(storageRoot, targetPath);
            
            // 模拟大数据写入
            Files.write(outputPath, content.getBytes(), StandardOpenOption.CREATE);
            return "Data imported to " + targetPath;
        } catch (Exception e) {
            return "Import failed: " + e.getMessage();
        }
    }

    /**
     * 安全版本示例（注释）
     * protected Path sanitizePath(String userInput) {
     *     Path result = Paths.get(storageRoot).resolve(userInput).normalize();
     *     if (!result.startsWith(storageRoot)) {
     *         throw new SecurityException("Invalid path");
     *     }
     *     return result;
     * }
     */

    // 模拟数据处理管道（声明式编程示例）
    public Stream<String> processLargeFile(String filename) throws IOException {
        Path filePath = Paths.get(storageRoot, filename);
        return Files.lines(filePath)
                   .map(line -> line.trim())
                   .filter(line -> !line.isEmpty());
    }

    // 模拟监控指标收集
    @GetMapping("/stats/{filename}")
    public Map<String, Object> getFileStats(@PathVariable String filename) {
        Map<String, Object> stats = new HashMap<>();
        try {
            Path filePath = Paths.get(storageRoot, filename);
            BasicFileAttributes attr = Files.readAttributes(filePath, BasicFileAttributes.class);
            
            stats.put("fileSize", attr.size());
            stats.put("lastModified", attr.lastModifiedTime());
            stats.put("lineCount", countLines(filePath));
        } catch (Exception e) {
            stats.put("error", e.getMessage());
        }
        return stats;
    }

    private long countLines(Path file) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(file)) {
            return reader.lines().count();
        }
    }
}