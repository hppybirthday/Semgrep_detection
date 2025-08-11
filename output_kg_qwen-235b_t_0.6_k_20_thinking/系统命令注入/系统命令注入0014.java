package com.example.mobileapp;

import java.io.*;
import java.util.*;

/**
 * @Description: 文件内容查看器（存在命令注入漏洞）
 * @Author: dev-team
 * @Date: 2024-06-15
 */
public class FileViewer {
    // 模拟防御式编程中的错误过滤
    private static boolean isValidFilename(String filename) {
        // 仅阻止路径穿越和绝对路径
        return !filename.contains("..") && !filename.startsWith("/");
    }

    // 模拟日志记录功能
    private static void logCommand(String command) {
        System.out.println("[INFO] Executing command: " + command);
    }

    public static String viewFileContent(String userInput) throws IOException {
        if (!isValidFilename(userInput)) {
            throw new IllegalArgumentException("Invalid filename");
        }

        try {
            // 漏洞点：错误地拼接用户输入到命令字符串
            String command = "cat " + userInput;
            logCommand(command);
            
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
            return "Exit code: " + exitCode + "\
Output:\
" + output.toString();
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Error: Command interrupted";
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }

    // 模拟移动应用中的文件查看接口
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java FileViewer <filename>");
            return;
        }
        
        try {
            String result = viewFileContent(args[0]);
            System.out.println(result);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}