package com.example.datacleaner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.Arrays;

@RestController
@RequestMapping("/clean")
public class DataCleanerController {
    private static final Logger logger = LoggerFactory.getLogger(DataCleanerController.class);

    @GetMapping("/process")
    public String processData(@RequestParam("file") String filePath, HttpServletResponse response) {
        // 模拟数据清洗服务调用
        if (filePath == null || filePath.isEmpty()) {
            return "文件路径不能为空";
        }

        try {
            // 使用Python脚本执行数据清洗
            ProcessBuilder pb = new ProcessBuilder();
            
            // 漏洞点：直接拼接用户输入到命令中
            String command = "python3 /scripts/data_cleaner.py " + filePath;
            
            if (System.getProperty("os.name").toLowerCase().startsWith("windows")) {
                pb.command("cmd.exe", "/c", command);
            } else {
                pb.command("sh", "-c", command);
            }

            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            logger.info("命令执行完成，退出码：{}", exitCode);
            
            if (exitCode == 0) {
                return "清洗成功：" + output.toString();
            } else {
                return "清洗失败，错误代码：" + exitCode;
            }
            
        } catch (Exception e) {
            logger.error("执行数据清洗失败", e);
            return "系统错误：" + e.getMessage();
        }
    }

    // 模拟数据清洗脚本
    @PostMapping("/setup")
    public String setupScript(@RequestBody String scriptContent) {
        // 实际应用中可能用于动态更新清洗脚本（存在严重风险）
        try {
            File tempScript = File.createTempFile("cleaner_", ".py");
            try (BufferedWriter writer = new BufferedWriter(
                new FileWriter(tempScript))) {
                writer.write(scriptContent);
            }
            return "脚本创建成功：" + tempScript.getAbsolutePath();
        } catch (IOException e) {
            return "脚本创建失败：" + e.getMessage();
        }
    }
}