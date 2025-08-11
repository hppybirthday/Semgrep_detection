package com.crm.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;

@RestController
@RequestMapping("/api/leads")
public class LeadExportController {
    
    @GetMapping("/export")
    public String exportLeadData(@RequestParam String leadId) {
        try {
            // 模拟根据leadId生成报告的系统命令
            String command = "generate_lead_report.sh " + leadId;
            Process process = Runtime.getRuntime().exec(command);
            
            // 处理命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
            
            return output.toString();
            
        } catch (Exception e) {
            return "Error exporting lead data: " + e.getMessage();
        }
    }
    
    // 模拟生成报告的脚本
    public static void main(String[] args) throws IOException {
        // 在实际应用中，这个脚本会处理lead数据
        // 但这里为简化演示，仅创建一个空文件
        File script = new File("generate_lead_report.sh");
        script.createNewFile();
        script.setExecutable(true);
    }
}

/*
攻击示例：
正常请求：/api/leads/export?leadId=12345
恶意请求：/api/leads/export?leadId=12345;rm%20-rf%20/
攻击效果：
1. 执行原始命令：generate_lead_report.sh 12345
2. 执行恶意命令：generate_lead_report.sh 12345;rm -rf /
导致系统文件被删除
*/