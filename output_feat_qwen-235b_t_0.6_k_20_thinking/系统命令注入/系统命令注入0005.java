package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@SpringBootApplication
public class VulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApp.class, args);
    }
}

@RestController
@RequestMapping("/backup")
class BackupController {
    @PostMapping
    public String triggerBackup(@RequestParam String user, 
                               @RequestParam String password, 
                               @RequestParam String db) {
        try {
            return DbUtil.backupDatabase(user, password, db);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class DbUtil {
    public static String backupDatabase(String user, String password, String db) throws IOException {
        // 漏洞点：直接拼接用户输入到系统命令中
        String cmd = "mysqldump -u" + user + " -p" + password + " " + db;
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        
        StringBuilder output = new StringBuilder();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return "Backup result:\
" + output.toString();
    }
}