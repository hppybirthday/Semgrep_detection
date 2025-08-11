package com.example.bank.controller;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/report")
public class ReportController {
    private static final Logger logger = Logger.getLogger(ReportController.class.getName());

    // 模拟银行交易记录查询接口
    @GetMapping("/generate")
    public String generateReport(@RequestParam String accountNo) {
        try {
            // 模拟数据库查询
            if (!isValidAccount(accountNo)) {
                return "Invalid account number";
            }

            // 构造命令执行脚本（存在漏洞）
            String[] cmd = {
                "/bin/sh",
                "-c",
                "./scripts/generate_report.sh " + accountNo + " > /var/reports/" + accountNo + ".txt"
            };

            DefaultExecutor executor = new DefaultExecutor();
            int exitValue = executor.execute(CommandLine.parse(cmd));
            
            if (exitValue == 0) {
                return "Report generated successfully";
            }
            return "Report generation failed";

        } catch (IOException e) {
            logger.severe("Command execution failed: " + e.getMessage());
            return "Internal server error";
        }
    }

    // 简化的账户验证逻辑（实际可能更复杂）
    private boolean isValidAccount(String accountNo) {
        // 模拟数据库查询
        String[] validAccounts = {"1234567890", "9876543210", "5555555555"};
        for (String acc : validAccounts) {
            if (acc.equals(accountNo)) {
                return true;
            }
        }
        return false;
    }

    // 模拟其他管理接口
    @PostMapping("/backup")
    public String backupData(@RequestParam String date) {
        return "Backup for " + date + " initiated";
    }
}