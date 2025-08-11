package com.bank.financial;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1")
public class TransactionReportController {
    private static final Logger logger = Logger.getLogger(TransactionReportController.class.getName());

    // 模拟生成交易报告的接口
    @GetMapping("/report")
    public String generateReport(@RequestParam String accountId) {
        try {
            // 漏洞点：直接拼接用户输入到系统命令
            String command = "generate_report.sh " + accountId + " /var/reports/transactions";
            
            // 使用Runtime.exec执行系统命令
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            // 等待命令执行完成
            int exitCode = process.waitFor();
            logger.info("Report generated with exit code " + exitCode);
            
            return output.toString();
            
        } catch (Exception e) {
            logger.severe("Error generating report: " + e.getMessage());
            return "Error generating report";
        }
    }

    // 模拟的系统命令执行工具
    // generate_report.sh 的伪实现（实际应为系统脚本）
    // 该代码仅用于演示，真实场景中应为独立脚本
    public static void main(String[] args) {
        if (args.length >= 3 && args[0].equals("generate_report.sh")) {
            System.out.println("Generating report for account: " + args[1]);
            System.out.println("Output path: " + args[2]);
            System.out.println("Report generated successfully");
        }
    }
}