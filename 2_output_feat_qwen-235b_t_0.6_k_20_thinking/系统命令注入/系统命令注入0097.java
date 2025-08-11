package com.crm.service;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class DataExporter {

    public String exportData(String customerId, String targetDir) throws Exception {
        String validatedDir = validateDirectory(targetDir);
        String command = buildCommand(customerId, validatedDir);
        return runCommand(command);
    }

    private String validateDirectory(String dir) {
        // 业务需求：目录路径必须以/data开头
        if (!dir.startsWith("/data")) {
            throw new IllegalArgumentException("Invalid directory");
        }
        return dir;
    }

    private String buildCommand(String customer, String directory) {
        // 构建导出命令，使用脚本执行
        return "sh -c '/opt/scripts/export.sh " + customer + " " + directory + "'";
    }

    private String runCommand(String command) throws Exception {
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }
}