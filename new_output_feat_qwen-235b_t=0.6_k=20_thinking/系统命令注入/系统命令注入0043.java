package com.bank.finance.backup;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@Controller
@RequestMapping("/db")
public class BackupController {
    @Autowired
    private BackupService backupService;

    /**
     * 数据库备份接口
     * 示例请求: /db/backup?user=admin&password=123456&db=finance_db
     */
    @GetMapping("/backup")
    @ResponseBody
    public String handleBackup(
            @RequestParam String user,
            @RequestParam String password,
            @RequestParam String db,
            HttpServletRequest request) {
        
        // 从请求头获取额外安全参数（伪装安全措施）
        String authHeader = request.getHeader("X-Backup-Auth");
        if (authHeader == null || !authHeader.equals("BANK_SEC_2023")) {
            return "Missing security header";
        }

        try {
            // 调用备份服务执行命令
            return backupService.executeBackup(user, password, db);
        } catch (Exception e) {
            return "Backup failed: " + e.getMessage();
        }
    }
}

@Service
class BackupService {
    private final CommandJobHandler jobHandler = new CommandJobHandler();

    // 生成备份命令（存在漏洞的关键点）
    String generateBackupCommand(String user, String password, String db) {
        // 伪装参数校验（存在校验绕过漏洞）
        if (user.length() > 20 || password.length() > 30) {
            throw new IllegalArgumentException("Input too long");
        }
        
        // 漏洞点：直接拼接命令参数（Windows平台）
        return "cmd.exe /c mysqldump -u" + user + " -p" + password + " " + db 
               + " > C:\\\\backup\\" + db + "_%date:~-4,4%%date:~-7,2%%date:~-10,2%.sql";
    }

    String executeBackup(String user, String password, String db) throws Exception {
        // 多层调用隐藏漏洞
        String command = generateBackupCommand(user, password, db);
        return jobHandler.runCommand(command);
    }
}

// 模拟任务处理类
class CommandJobHandler {
    String runCommand(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(command);
        
        // 读取命令执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}