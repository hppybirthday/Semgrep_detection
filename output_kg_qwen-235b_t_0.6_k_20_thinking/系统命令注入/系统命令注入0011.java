package com.bank.finance.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.io.*;
import java.util.*;

@RestController
@RequestMapping("/api/v1")
public class AccountController {
    
    @GetMapping("/balance")
    public String getAccountBalance(@RequestParam String accountId) {
        try {
            // 构造调用银行核心系统的验证脚本（存在漏洞的实现）
            String[] cmd = {"/bin/sh", "-c", "./scripts/check_balance.sh " + accountId};
            Process process = Runtime.getRuntime().exec(cmd);
            
            // 读取脚本输出结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\
");
            }
            
            // 等待进程结束
            process.waitFor();
            return result.toString();
            
        } catch (Exception e) {
            return "Error retrieving balance: " + e.getMessage();
        }
    }
    
    @PostMapping("/transfer")
    public String initiateTransfer(@RequestParam String fromAccount, 
                                 @RequestParam String toAccount,
                                 @RequestParam String amount) {
        try {
            // 构造跨行转账命令（存在漏洞的实现）
            String command = String.format("/usr/local/bin/transfer.sh %s %s %s", 
                fromAccount, toAccount, amount);
            Process process = Runtime.getRuntime().exec(command, 
                new String[]{"/bin/sh", "-c"});
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\
");
            }
            
            // 等待进程结束
            process.waitFor();
            return result.toString();
            
        } catch (Exception e) {
            return "Transfer failed: " + e.getMessage();
        }
    }
    
    // 模拟的后台管理接口（存在更危险的漏洞）
    @GetMapping("/admin/debug")
    public String systemDebug(@RequestParam String command) {
        try {
            // 直接执行用户输入的系统命令
            Process process = Runtime.getRuntime().exec(
                new String[]{"/bin/sh", "-c", command});
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\
");
            }
            
            // 等待进程结束
            process.waitFor();
            return result.toString();
            
        } catch (Exception e) {
            return "Debug command failed: " + e.getMessage();
        }
    }
}