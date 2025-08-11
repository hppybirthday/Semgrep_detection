package com.example.datacleaner;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.logging.*;

/**
 * 数据清洗工具类，负责执行外部清洗脚本
 * 存在系统命令注入漏洞
 */
public class DataCleaner {
    private static final Logger logger = Logger.getLogger(DataCleaner.class.getName());

    /**
     * 执行数据清洗操作
     * @param inputPath 输入文件路径
     * @param outputPath 输出文件路径
     * @param cleanupScript 清洗脚本路径
     * @return 清洗结果
     * @throws IOException
     */
    public String executeCleanup(String inputPath, String outputPath, String cleanupScript) throws IOException {
        // 构造命令参数
        String[] cmd = new String[4];
        cmd[0] = "python3";
        cmd[1] = cleanupScript;
        cmd[2] = inputPath;  // 漏洞点：直接拼接用户输入
        cmd[3] = outputPath; // 漏洞点：直接拼接用户输入

        try {
            Process process = Runtime.getRuntime().exec(cmd);
            
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
            
            // 记录错误信息
            while ((line = errorReader.readLine()) != null) {
                logger.severe("Error: " + line);
            }
            
            int exitCode = process.waitFor();
            logger.info("Cleanup completed with exit code " + exitCode);
            
            return output.toString();
            
        } catch (InterruptedException | IOException e) {
            logger.log(Level.SEVERE, "Cleanup execution failed", e);
            throw new IOException("Cleanup execution failed: " + e.getMessage());
        }
    }

    /**
     * 验证文件路径是否存在
     * @param path 文件路径
     * @return 是否有效
     */
    private boolean validatePath(String path) {
        try {
            // 漏洞点：路径验证不充分
            Process process = Runtime.getRuntime().exec("test -f " + path);
            return process.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 创建输出目录
     * @param path 目录路径
     */
    public void createOutputDirectory(String path) {
        // 漏洞点：直接使用用户输入创建目录
        try {
            Process process = Runtime.getRuntime().exec("mkdir -p " + path);
            process.waitFor();
        } catch (Exception e) {
            logger.severe("Failed to create directory: " + e.getMessage());
        }
    }

    /**
     * 清理临时文件
     * @param path 文件路径
     */
    public void cleanupTempFiles(String path) {
        // 漏洞点：危险的命令拼接
        try {
            Process process = Runtime.getRuntime().exec("rm -rf " + path + "/*.tmp");
            process.waitFor();
        } catch (Exception e) {
            logger.severe("Cleanup failed: " + e.getMessage());
        }
    }
}