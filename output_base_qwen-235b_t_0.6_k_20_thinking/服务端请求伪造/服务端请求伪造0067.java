package com.taskmanager.domain;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

// 实体类
public class Task {
    private String id;
    private String description;
    private String callbackUrl; // 漏洞点：用户可控的回调URL

    public Task(String id, String description, String callbackUrl) {
        this.id = id;
        this.description = description;
        this.callbackUrl = callbackUrl;
    }

    // 领域服务
    public static class TaskService {
        private NotificationService notificationService = new NotificationService();

        public void completeTask(Task task) {
            // 业务逻辑处理
            System.out.println("Task completed: " + task.getDescription());
            
            // 触发漏洞的调用
            notificationService.sendCompletionNotification(task.callbackUrl);
        }
    }

    // 基础设施服务
    static class NotificationService {
        void sendCompletionNotification(String callbackUrl) {
            try {
                URL url = new URL(callbackUrl);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("POST");
                connection.setDoOutput(true);
                
                // 漏洞利用点：直接使用用户输入的URL发起请求
                try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()))) {
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    System.out.println("Notification response: " + response);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    // 应用层示例
    public static void main(String[] args) {
        // 模拟用户输入（攻击者注入内部地址）
        Task task = new Task(
            "T001", 
            "SSRF Vulnerable Task", 
            "http://localhost:8080/internal/admin" // 攻击载荷
        );
        
        new TaskService().completeTask(task);
    }
}