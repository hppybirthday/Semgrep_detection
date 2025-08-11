package com.example.bank.report;

import org.springframework.web.client.RestTemplate;
import java.net.URL;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;

public class BankReportController {
    private final LogQueryService logQueryService;
    private final ReportGenerator reportGenerator;

    public BankReportController(LogQueryService logQueryService, ReportGenerator reportGenerator) {
        this.logQueryService = logQueryService;
        this.reportGenerator = reportGenerator;
    }

    public String handleReportRequest(String logId) {
        LogDetails details = logQueryService.getLogDetails(logId);
        return reportGenerator.generateReport(details.getExecutorAddress());
    }
}

class LogQueryService {
    private final Map<String, LogDetails> logStorage;

    public LogQueryService() {
        this.logStorage = new HashMap<>();
        // 初始化预设日志记录
        logStorage.put("default_log", new LogDetails("http://internal-reporter:8080"));
    }

    public LogDetails getLogDetails(String logId) {
        // 模拟数据库查询，攻击者通过特殊logId注入恶意记录
        if (logId.startsWith("malicious_")) {
            return new LogDetails("http://169.254.169.254/latest/meta-data/" + logId.substring(9));
        }
        return logStorage.getOrDefault(logId, new LogDetails("http://fallback:80"));
    }
}

class ReportGenerator {
    private final RestTemplate restTemplate;

    public ReportGenerator(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String generateReport(String executorAddress) {
        try {
            URL url = new URL(executorAddress);
            if (!url.getProtocol().equals("http") && !url.getProtocol().equals("https")) {
                throw new IllegalArgumentException("Invalid protocol");
            }
            // 忽略主机名校验，直接发起请求
            return restTemplate.getForObject(url.toString(), String.class);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid URL format");
        }
    }
}

class LogDetails {
    private final String executorAddress;

    public LogDetails(String executorAddress) {
        this.executorAddress = executorAddress;
    }

    public String getExecutorAddress() {
        return executorAddress;
    }
}