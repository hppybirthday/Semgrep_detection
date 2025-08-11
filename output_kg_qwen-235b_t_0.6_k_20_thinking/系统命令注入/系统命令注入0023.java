package com.gamestudio.example;

import java.io.*;

/**
 * @Description: 桌面游戏存档管理器
 * @Author: dev-team
 * @Date: 2024/5/20
 */
public class GameManager {
    private static final String SAVE_DIR = "./saves/";

    public static void main(String[] args) {
        try {
            System.out.println("=== 桌面游戏存档管理系统 ===");
            System.out.print("请输入存档名称: ");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String saveName = reader.readLine();
            
            if (saveName == null || saveName.trim().isEmpty()) {
                System.out.println("存档名称不能为空");
                return;
            }
            
            // 创建存档目录
            CommandExecutor executor = new CommandExecutor();
            String result = executor.createSaveDirectory(saveName);
            System.out.println("操作结果: " + result);
            
        } catch (Exception e) {
            System.err.println("发生致命错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

class CommandExecutor {
    /**
     * 创建存档目录（存在命令注入漏洞）
     */
    public String createSaveDirectory(String saveName) throws IOException {
        // 构造系统命令（漏洞点）
        String command = "mkdir -p " + GameManager.SAVE_DIR + saveName;
        
        try {
            System.out.println("执行命令: " + command);
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取命令输出
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
                output.append("[ERROR] ").append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            return output.toString() + "退出代码: " + exitCode;
            
        } catch (Exception e) {
            throw new IOException("命令执行失败: " + e.getMessage(), e);
        }
    }
}