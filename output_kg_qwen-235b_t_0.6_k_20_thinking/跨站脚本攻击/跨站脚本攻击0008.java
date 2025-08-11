package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/report")
public class DataReportController {
    private final ReportService reportService = new ReportService();

    @GetMapping("/generate")
    public String generateReport(@RequestParam String name, @RequestParam String content) {
        return reportService.generateReport(name, content);
    }

    public static void main(String[] args) {
        SpringApplication.run(DataReportController.class, args);
    }
}

class ReportService {
    private final ReportGenerator reportGenerator = new UnsafeHtmlGenerator();

    public String generateReport(String name, String content) {
        // 模拟大数据处理过程
        List<String> processedData = processData(content);
        return reportGenerator.generateHtmlReport(name, processedData);
    }

    private List<String> processData(String rawData) {
        // 简化的大数据处理逻辑
        List<String> result = new ArrayList<>();
        for (String item : rawData.split(",")) {
            result.add(item.trim() + "_processed");
        }
        return result;
    }
}

interface ReportGenerator {
    String generateHtmlReport(String name, List<String> data);
}

class UnsafeHtmlGenerator implements ReportGenerator {
    @Override
    public String generateHtmlReport(String name, List<String> data) {
        StringBuilder html = new StringBuilder();
        html.append("<html><head><title>").append(name).append("</title></head>");
        html.append("<body><h1>Report: ").append(name).append("</h1>");
        html.append("<ul>");
        for (String item : data) {
            html.append("<li>").append(item).append("</li>");
        }
        html.append("</ul></body></html>");
        return html.toString();
    }
}

class SafeHtmlGenerator implements ReportGenerator {
    @Override
    public String generateHtmlReport(String name, List<String> data) {
        // 安全实现应包含HTML转义逻辑
        return "Secure implementation not shown here";
    }
}