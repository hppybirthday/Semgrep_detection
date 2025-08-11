package com.example.vulnerableapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@SpringBootApplication
@EnableScheduling
public class CommandInjectionDemo {
    public static void main(String[] args) {
        SpringApplication.run(CommandInjectionDemo.class, args);
    }

    @RestController
    @RequestMapping("/logs")
    public static class LogController {
        @Autowired
        private LogService logService;

        @GetMapping("/delete/{logName}")
        public String deleteLog(@PathVariable String logName) {
            return logService.deleteLogFile(logName);
        }
    }

    @Service
    public static class LogService {
        // 模拟定时任务每天凌晨清理日志
        @Scheduled(cron = "0 0 0 * * ?")
        public void scheduledCleanup() {
            executeCommand("cleanup_script.sh");
        }

        public String deleteLogFile(String logName) {
            // 错误的防御逻辑：仅检查路径穿越
            if (logName.contains("../")) {
                return "Invalid log name";
            }
            
            // 漏洞点：直接拼接用户输入到命令中
            String command = "sh -c \\"rm -rf /var/logs/" + logName + "\\"";
            return executeCommand(command);
        }

        private String executeCommand(String cmd) {
            try {
                Process process = Runtime.getRuntime().exec(cmd);
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
                return output.toString();
            } catch (IOException e) {
                return "Error executing command: " + e.getMessage();
            }
        }
    }
}