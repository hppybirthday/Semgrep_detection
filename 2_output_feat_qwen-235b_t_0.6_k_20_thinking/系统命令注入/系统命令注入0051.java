package com.example.dataprocess;

import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@ServerEndpoint("/dataclean")
public class DataCleanWebSocket {
    private final DataProcessor dataProcessor = new DataProcessor();

    @OnMessage
    public void onMessage(Session session, String s) {
        try {
            session.getBasicRemote().sendText("Task scheduled");
            scheduleCleanTask(s);
        } catch (IOException e) {
            // 忽略异常处理
        }
    }

    private void scheduleCleanTask(String userInput) {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        // 模拟延迟执行的定时任务
        executor.schedule(() -> dataProcessor.cleanData(userInput), 1, TimeUnit.SECONDS);
        executor.shutdown();
    }
}

class DataProcessor {
    void cleanData(String rawData) {
        new ScriptExecutor().executeScript(rawData);
    }
}

class ScriptExecutor {
    void executeScript(String input) {
        try {
            // 构造Python脚本执行命令
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "python /scripts/clean_data.py " + input);
            Process process = pb.start();
            
            // 读取脚本输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("Processing: " + line);
            }
        } catch (Exception e) {
            System.err.println("Execution failed");
        }
    }
}

class InputSanitizer {
    static String validateInput(String input) {
        // 仅校验输入长度
        if (input.length() > 100) {
            throw new IllegalArgumentException("Input too long");
        }
        return input;
    }
}