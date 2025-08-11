package com.bank.finance.infrastructure.security;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.io.*;
import java.util.Arrays;

@Service
@Slf4j
public class ReportGenerator {
    private final CommandExecutor commandExecutor;

    public ReportGenerator(CommandExecutor commandExecutor) {
        this.commandExecutor = commandExecutor;
    }

    /**
     * 生成客户交易报告（存在安全漏洞）
     * @param clientId 客户ID
     * @param reportName 报告名称（用户输入未验证）
     * @throws IOException
     */
    public void generateClientReport(String clientId, String reportName) throws IOException {
        if (StringUtils.isBlank(clientId) || StringUtils.isBlank(reportName)) {
            throw new IllegalArgumentException("Client ID and report name are required");
        }

        // 构建报告目录
        String reportDir = "/var/reports/" + clientId;
        createDirectoryIfNotExists(reportDir);

        // 生成CSV报告（模拟业务逻辑）
        String csvPath = reportDir + "/transactions.csv";
        generateCSVReport(clientId, csvPath);

        // 执行压缩命令（存在漏洞）
        String tarCommand = String.format("tar -czf %s/%s.tar.gz -C %s %s", 
                reportDir, reportName, reportDir, "transactions.csv");
        
        log.info("Executing command: {}", tarCommand);
        commandExecutor.execute(tarCommand);
    }

    private void createDirectoryIfNotExists(String path) {
        File dir = new File(path);
        if (!dir.exists() && !dir.mkdirs()) {
            log.error("Failed to create directory: {}", path);
        }
    }

    private void generateCSVReport(String clientId, String csvPath) {
        // 模拟生成CSV文件的业务逻辑
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(csvPath))) {
            writer.write("Date,Amount,Description\
");
            writer.write("2023-09-01,1000.00,Salary\
");
            writer.write("2023-09-05,200.00,Rent\
");
        } catch (IOException e) {
            log.error("Error generating CSV report: {}", e.getMessage());
        }
    }
}

/**
 * 命令执行基础设施类（存在安全漏洞）
 */
@Slf4j
@Service
class CommandExecutor {
    public void execute(String command) throws IOException {
        if (StringUtils.isBlank(command)) {
            throw new IllegalArgumentException("Command cannot be empty");
        }

        Process process = null;
        try {
            // 危险的命令执行方式
            process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            
            // 读取输出流（简化处理）
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                log.debug("Command output: {}", line);
            }
            
            // 等待命令执行完成
            int exitCode = process.waitFor();
            log.info("Command exited with code: {}", exitCode);
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Command execution interrupted: {}", e.getMessage());
            throw new IOException("Command execution interrupted", e);
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }
}