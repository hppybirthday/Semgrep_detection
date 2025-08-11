package com.bank.financialsystem.report;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

// 领域实体
public class TransactionReport {
    private String content;
    private String reportId;

    public TransactionReport(String reportId, String content) {
        this.reportId = reportId;
        this.content = content;
    }

    // 漏洞点：领域服务直接处理文件路径
    public void generateAndSaveReport(String baseDir, String filename) throws IOException {
        String fullPath = baseDir + File.separator + filename;
        try (FileWriter writer = new FileWriter(fullPath)) {
            writer.write(content);
        }
    }
}

// 应用服务
class ReportManagementService {
    private ReportRepository repository;

    public ReportManagementService(ReportRepository repository) {
        this.repository = repository;
    }

    // 漏洞触发点：外部输入直接传递给领域实体
    public void createReport(String reportId, String content, String baseDir, String userInputFilename) throws IOException {
        TransactionReport report = new TransactionReport(reportId, content);
        // 危险操作：将用户输入的文件名直接传递给领域实体
        report.generateAndSaveReport(baseDir, userInputFilename);
    }
}

// 仓储接口
interface ReportRepository {
    void save(TransactionReport report);
}

// 文件系统实现
class FileReportRepository implements ReportRepository {
    private String storagePath;

    public FileReportRepository(String storagePath) {
        this.storagePath = storagePath;
    }

    @Override
    public void save(TransactionReport report) {
        try {
            // 使用固定文件名保证示例可运行
            report.generateAndSaveReport(storagePath, "report_" + report.reportId + ".txt");
        } catch (IOException e) {
            throw new RuntimeException("File operation failed", e);
        }
    }
}

// 模拟配置类
class AppConfig {
    public static final String REPORT_DIR = "/var/bank/reports";
}
