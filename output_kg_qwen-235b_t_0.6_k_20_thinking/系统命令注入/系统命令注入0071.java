package com.example.game;

import java.io.*;
import java.util.Arrays;
import java.util.logging.Logger;

/**
 * 桌面游戏启动器
 * 存在系统命令注入漏洞的示例
 */
public class GameLauncher {
    private static final Logger logger = Logger.getLogger(GameLauncher.class.getName());

    public static void main(String[] args) {
        try {
            // 模拟用户输入（实际可能来自配置文件或网络请求）
            String userInput = System.getProperty("os.name").toLowerCase().contains("win") 
                ? "classic & calc.exe"  // Windows示例
                : "classic; rm -rf /tmp/test"; // Linux示例

            logger.info("[启动调试模式] 接收用户参数: " + userInput);

            // 漏洞点：直接拼接用户输入到命令参数中
            String[] command = {
                "java", "-jar", "game_engine.jar",
                "--mode", userInput,
                "--resolution", "1920x1080",
                "--fullscreen", "true"
            };

            logger.info("[启动调试模式] 执行命令: " + String.join(" ", command));

            // 使用ProcessBuilder执行游戏启动命令
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            // 读取命令执行输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                logger.info("[游戏输出] " + line);
            }

            int exitCode = process.waitFor();
            logger.info("[系统提示] 游戏进程退出代码: " + exitCode);

        } catch (Exception e) {
            logger.severe("[致命错误] 启动器异常: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // 模拟游戏引擎的参数解析函数
    static class GameEngine {
        void parseArgs(String[] args) {
            for (String arg : args) {
                if (arg.startsWith("--mode")) {
                    // 危险的参数处理方式
                    String mode = arg.split("=")[1];
                    System.out.println("加载游戏模式: " + mode);
                }
            }
        }
    }
}