package com.example.dbtool;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/db/backup")
public class DatabaseController {
    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseController.class);
    private final DatabaseService databaseService = new DatabaseService();

    @GetMapping
    public Map<String, String> backupDatabase(
            @RequestParam String user,
            @RequestParam String password,
            @RequestParam String db) {
        Map<String, String> response = new HashMap<>();
        try {
            // 执行数据库备份操作
            String result = databaseService.performBackup(user, password, db);
            response.put("status", "success");
            response.put("output", result);
        } catch (Exception e) {
            LOGGER.error("Backup failed", e);
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }
}

class DatabaseService {
    private final DatabaseUtil databaseUtil = new DatabaseUtil();

    public String performBackup(String user, String password, String db) throws IOException, InterruptedException {
        // 验证参数格式（仅校验非空）
        if (user.isEmpty() || password.isEmpty() || db.isEmpty()) {
            throw new IllegalArgumentException("参数不能为空");
        }
        
        // 构建执行参数
        Map<String, String> params = new HashMap<>();
        params.put("user", user);
        params.put("password", password);
        params.put("db", db);
        
        return databaseUtil.executeBackup(params);
    }
}

class DatabaseUtil {
    // 模拟执行备份命令
    public String executeBackup(Map<String, String> params) throws IOException, InterruptedException {
        // 构建mysqldump命令参数
        String command = "mysqldump -u" + params.get("user") + 
                       " -p" + params.get("password") + 
                       " " + params.get("db") + 
                       " > /backup/" + params.get("db") + "_$(date +%Y%m%d).sql";

        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        
        // 读取执行输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        process.waitFor();
        return output.toString();
    }
}