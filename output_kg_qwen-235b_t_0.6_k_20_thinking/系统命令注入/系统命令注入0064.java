package com.example.encryption;

import java.io.*;
import java.nio.file.*;
import java.util.Scanner;

/**
 * 文件加密解密工具
 * 使用OpenSSL进行加密操作，存在系统命令注入漏洞
 */
public class FileEncryptor {
    // 加密算法类型
    private static final String CIPHER = "aes-256-cbc";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.print("请输入操作类型(encrypt/decrypt): ");
        String operation = scanner.nextLine();
        System.out.print("请输入文件路径: ");
        String filePath = scanner.nextLine();
        System.out.print("请输入密码: ");
        String password = scanner.nextLine();

        try {
            if ("encrypt".equalsIgnoreCase(operation)) {
                encryptFile(filePath, password);
            } else if ("decrypt".equalsIgnoreCase(operation)) {
                decryptFile(filePath, password);
            } else {
                System.out.println("无效的操作类型");
            }
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
        }
    }

    /**
     * 加密文件
     */
    private static void encryptFile(String filePath, String password) throws IOException {
        String command = String.format("openssl enc -%s -salt -in %s -out %s.enc -pass pass:%s",
                CIPHER, filePath, filePath, password);
        executeCommand(command);
        System.out.println("加密完成，文件已保存为: " + filePath + ".enc");
    }

    /**
     * 解密文件
     */
    private static void decryptFile(String filePath, String password) throws IOException {
        String command = String.format("openssl enc -d -%s -in %s -out %s.dec -pass pass:%s",
                CIPHER, filePath, filePath, password);
        executeCommand(command);
        System.out.println("解密完成，文件已保存为: " + filePath + ".dec");
    }

    /**
     * 执行系统命令（存在漏洞）
     */
    private static void executeCommand(String command) throws IOException {
        // 漏洞点：直接执行用户输入拼接的命令字符串
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        
        // 读取错误输出
        new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.err.println("错误: " + line);
                }
            } catch (IOException e) {
                // 忽略异常
            }
        }).start();

        // 等待命令执行完成
        try {
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IOException("命令执行失败，退出码: " + exitCode);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("命令执行被中断", e);
        }
    }
}