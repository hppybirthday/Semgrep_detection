package com.example.bank.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.beans.factory.annotation.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Map;
import java.util.HashMap;

@Controller
public class FinancialReportController {
    private static final Logger logger = LoggerFactory.getLogger(FinancialReportController.class);
    
    @Value("${external.report.service}")
    private String externalReportService;

    // 声明式编程配置示例
    @GetMapping("/generateReport")
    public String generateReport(@RequestParam String reportType, 
                               @RequestParam String callbackUrl,
                               Model model) {
        try {
            // 构造外部服务请求
            String reportEndpoint = String.format("%s/api/report/%s", externalReportService, reportType);
            
            // 使用RestTemplate发起外部请求（存在漏洞的关键点）
            RestTemplate restTemplate = new RestTemplate();
            
            // 直接使用用户提供的callbackUrl进行服务端请求
            ResponseEntity<String> response = restTemplate.getForEntity(
                new URI(callbackUrl), String.class);

            // 将外部服务结果作为参数传递给视图
            model.addAttribute("externalData", response.getBody());
            model.addAttribute("status", "success");
            
        } catch (Exception e) {
            logger.error("Report generation failed: {}", e.getMessage());
            model.addAttribute("status", "error");
            model.addAttribute("error", e.getMessage());
        }
        
        // 返回报告生成结果页面
        return "reportResult";
    }

    // 声明式视图配置
    @GetMapping("/report/form")
    public String showReportForm(Model model) {
        model.addAttribute("reportTypes", getAvailableReportTypes());
        return "reportForm";
    }

    // 模拟可用报告类型
    private Map<String, String> getAvailableReportTypes() {
        Map<String, String> types = new HashMap<>();
        types.put("daily", "Daily Transaction Summary");
        types.put("monthly", "Monthly Financial Statement");
        types.put("audit", "Compliance Audit Report");
        return types;
    }

    // 声明式异常处理
    @ExceptionHandler({Exception.class})
    public String handleException() {
        return "error/500";
    }
}