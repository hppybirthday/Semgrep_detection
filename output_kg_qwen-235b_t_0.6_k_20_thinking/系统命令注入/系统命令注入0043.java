package com.bank.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Logger;

/**
 * 银行文件处理系统 - 存在命令注入漏洞的版本
 */
public class BankFileProcessor {
    private static final Logger logger = Logger.getLogger("BankFileProcessor");
    
    // 模拟处理用户上传的交易文件
    public void processUserFile(String filename) {
        try {
            String command = "cat " + filename;
            logger.info("Executing command: " + command);
            CommandExecutor.execCommand(command);
        } catch (Exception e) {
            logger.severe("Processing failed: " + e.getMessage());
        }
    }
    
    // 模拟后台命令执行器
    static class CommandExecutor {
        public static void execCommand(String cmd) throws IOException {
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("[System Output] " + line);
            }
            
            try {
                int exitCode = process.waitFor();
                logger.info("Command exited with code " + exitCode);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}

// 模拟API接口
class FileProcessingAPI {
    private BankFileProcessor processor = new BankFileProcessor();
    
    // 模拟用户上传文件接口
    public void uploadUserFile(String userInput) {
        // 不当的输入处理
        processor.processUserFile(userInput);
    }
}

// 测试类
public class VulnerableBankApp {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java VulnerableBankApp <filename>");
            return;
        }
        
        FileProcessingAPI api = new FileProcessingAPI();
        api.uploadUserFile(args[0]);
    }
}