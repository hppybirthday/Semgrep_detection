package com.gamestudio.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

// 领域模型：游戏存档处理器
public class GameArchiveHandler {
    private final CommandExecutor commandExecutor;

    public GameArchiveHandler() {
        this.commandExecutor = new CommandExecutor();
    }

    // 应用服务：处理用户存档操作
    public void processArchive(String archiveName) {
        // 漏洞点：直接拼接用户输入到系统命令
        String command = "zip -r /game_data/archives/" + archiveName + " /game_data/savegames/*";
        commandExecutor.executeCommand(command);
    }

    // 基础设施：命令执行器
    private static class CommandExecutor {
        public void executeCommand(String command) {
            try {
                ProcessBuilder pb = new ProcessBuilder("/bin/bash", "-c", command);
                Process process = pb.start();
                
                // 读取命令执行结果
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()));
                
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("[STDOUT] " + line);
                }
                while ((line = errorReader.readLine()) != null) {
                    System.err.println("[STDERR] " + line);
                }
                
                int exitCode = process.waitFor();
                System.out.println("Command exited with code " + exitCode);
                
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    // 模拟用户接口
    public static void main(String[] args) {
        GameArchiveHandler handler = new GameArchiveHandler();
        
        // 模拟用户输入（攻击载荷包含命令注入）
        String userInput = "normal_archive; rm -rf /game_data/*";
        System.out.println("Processing archive: " + userInput);
        handler.processArchive(userInput);
    }
}

// 领域服务接口
interface ArchiveService {
    void createArchive(String name);
    void verifyArchiveIntegrity(String name);
}

// 领域实体
class GameArchive {
    private String name;
    private long size;
    private String checksum;

    // 领域规则验证
    public boolean isValidArchiveName(String name) {
        // 本应在此进行输入验证（但被遗漏）
        return name.matches("[a-zA-Z0-9_-]+");
    }
}