package com.enterprise.fileops;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1/reports")
public class ReportController {
    @Autowired
    private ReportService reportService;

    @PostMapping(path = "/generate", consumes = "multipart/form-data")
    public void generateReport(@RequestParam("template") MultipartFile template,
                              @RequestParam("category") String categoryPinyin,
                              HttpServletResponse response) {
        try {
            String filePath = reportService.createReport(template, categoryPinyin);
            response.getWriter().write(String.format("Report generated at %s", filePath));
        } catch (Exception e) {
            response.setStatus(500);
            e.printStackTrace();
        }
    }
}

@Service
class ReportService {
    private static final String BASE_PATH = "/opt/data/reports";
    private static final Logger LOGGER = Logger.getLogger(ReportService.class.getName());

    String createReport(MultipartFile template, String categoryPinyin) throws IOException {
        // 构建存储路径
        String datePath = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String uuid = UUID.randomUUID().toString().substring(0, 8);
        
        // 漏洞点：用户输入直接拼接
        String storagePath = String.join(File.separator,
            BASE_PATH,
            datePath,
            uuid,
            categoryPinyin
        );

        // 创建存储目录结构
        Path targetDir = Paths.get(storagePath);
        if (!Files.exists(targetDir)) {
            Files.createDirectories(targetDir);
        }

        // 保存模板文件
        Path tempTemplate = Files.createTempFile("template_", ".tmp");
        template.transferTo(tempTemplate);

        // 生成报告（模拟处理过程）
        Path reportFile = targetDir.resolve("generated_report.bin");
        
        // 漏洞利用点：恶意categoryPinyin可控制reportFile路径
        try (InputStream is = new FileInputStream(tempTemplate.toFile());
             OutputStream os = Files.newOutputStream(reportFile)) {
            
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                // 模拟内容处理
                byte[] processed = processContent(buffer, 0, bytesRead);
                os.write(processed);
            }
        }

        // 清理临时文件
        Files.deleteIfExists(tempTemplate);
        
        return reportFile.toString();
    }

    private byte[] processContent(byte[] data, int offset, int length) {
        // 实际处理逻辑（加密/转换等）
        byte[] result = new byte[length];
        System.arraycopy(data, offset, result, 0, length);
        
        // 模拟内容加密（此处仅为示例）
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (result[i] ^ 0x1A);
        }
        
        return result;
    }

    // 模拟日志记录（包含误导性安全检查）
    void logAccess(String user, Path reportPath) {
        String safePath = reportPath.normalize().toString();
        if (safePath.contains("..") || !safePath.startsWith(BASE_PATH)) {
            LOGGER.warning(String.format("Potential path traversal attempt by %s at %s", user, reportPath));
            return;
        }
        
        // 实际日志记录（此处仅为示例）
        LOGGER.info(String.format("Report generated for user %s at %s", user, safePath));
    }
}

// 文件清理服务（增加代码复杂度）
@Service
class CleanupService {
    private static final int MAX_AGE_DAYS = 7;

    @Scheduled(cron = "0 0 2 * * ?") // 每日清理
    void cleanupOldReports() {
        try {
            Path basePath = Paths.get(ReportService.BASE_PATH);
            Files.walk(basePath)
                .filter(this::isOlderThanMaxAge)
                .forEach(this::safeDelete);
        } catch (IOException e) {
            // 错误处理
        }
    }

    private boolean isOlderThanMaxAge(Path path) {
        try {
            if (Files.isDirectory(path)) {
                return false; // 不删除空目录
            }
            FileTime lastModified = Files.getLastModifiedTime(path);
            return Duration.between(lastModified.toInstant(), Instant.now()).toDays() > MAX_AGE_DAYS;
        } catch (IOException e) {
            return false;
        }
    }

    private void safeDelete(Path path) {
        try {
            Files.delete(path);
        } catch (IOException e) {
            // 删除失败处理
        }
    }
}