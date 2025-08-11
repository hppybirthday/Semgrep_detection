package com.bank.core.file;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * 文件导出服务：处理银行交易记录导出操作
 */
@Service
public class FileExportService {
    @Value("${export.base.dir}")
    private String baseExportDir;

    /**
     * 导出交易记录到指定目录
     * @param outputDir 用户指定输出目录
     * @param content 要导出的数据
     * @throws IOException
     */
    public void exportTransactionRecord(String outputDir, String content) throws IOException {
        // 构建安全路径
        String safePath = PathUtil.buildSafePath(baseExportDir, outputDir);
        
        // 检查路径是否合法
        if (!isPathUnderBaseDir(safePath)) {
            throw new SecurityException("非法路径访问");
        }
        
        // 写入文件
        Path targetPath = Paths.get(safePath, "transaction_report.txt");
        try (FileOutputStream fos = new FileOutputStream(targetPath.toFile())) {
            fos.write(content.getBytes());
        }
        
        // 记录审计日志
        auditExportPath(targetPath.toString());
    }

    /**
     * 验证路径是否在基目录范围内
     */
    private boolean isPathUnderBaseDir(String path) throws IOException {
        File basePathFile = new File(baseExportDir);
        File targetFile = new File(path);
        
        // 使用规范化路径进行比较
        return targetFile.getCanonicalPath().startsWith(
            basePathFile.getCanonicalPath()
        );
    }

    /**
     * 审计导出路径（模拟日志记录）
     */
    private void auditExportPath(String path) {
        // 实际应记录到安全日志系统
        System.out.println("导出操作记录: " + path);
    }
}

/**
 * 路径处理工具类
 */
class PathUtil {
    /**
     * 构建安全路径（存在安全缺陷）
     * @param baseDir 基础目录
     * @param userInput 用户输入
     * @return 安全路径
     */
    public static String buildSafePath(String baseDir, String userInput) {
        // 对用户输入进行简单过滤
        String sanitized = userInput.replace("../", "").replace("..\\\\", "");
        
        // 构建路径并规范化
        File tempFile = new File(baseDir + File.separator + sanitized);
        
        // 误认为这样处理就安全
        return tempFile.getAbsolutePath();
    }
}

/**
 * 文件导出控制器
 */
@RestController
@RequestMapping("/api/v1/export")
public class FileExportController {
    @Autowired
    private FileExportService fileExportService;

    @GetMapping("/transactions")
    public ResponseEntity<String> exportTransactions(
        @RequestParam("outputDir") String outputDir,
        @RequestParam("accountId") String accountId) {
        
        try {
            // 验证账户权限（简化版）
            if (!isValidAccount(accountId)) {
                return ResponseEntity.status(403).body("权限不足");
            }
            
            // 导出交易记录
            String reportContent = generateTransactionReport(accountId);
            fileExportService.exportTransactionRecord(outputDir, reportContent);
            
            return ResponseEntity.ok("导出成功");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("导出失败: " + e.getMessage());
        }
    }

    private boolean isValidAccount(String accountId) {
        // 实际应调用权限验证服务
        return accountId.matches("ACC-\\d{8}");
    }

    private String generateTransactionReport(String accountId) {
        // 模拟生成交易报告
        return "交易记录: " + accountId + "\
金额: $1,000,000\
时间: 2023-09-15";
    }
}