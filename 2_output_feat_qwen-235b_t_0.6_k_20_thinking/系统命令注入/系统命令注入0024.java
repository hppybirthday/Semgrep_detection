package com.bank.core.backup;

import org.apache.commons.io.IOUtils;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@RestController
@RequestMapping("/api/backup")
public class BackupController {
    private final BackupService backupService = new BackupService();

    /**
     * 数据库备份接口
     * @param dbNames 数据库名称列表（逗号分隔）
     * @param response 输出流
     */
    @GetMapping("/mysql")
    public void createBackup(@RequestParam String dbNames, HttpServletResponse response) throws IOException {
        response.setContentType("application/octet-stream");
        String result = backupService.executeBackup(dbNames);
        IOUtils.write(result, response.getOutputStream(), StandardCharsets.UTF_8);
    }
}

class BackupService {
    private static final String MYSQL_DUMP_PATH = "/usr/bin/mysqldump";
    private static final String BACKUP_DIR = "/var/backups/mysql";

    /**
     * 执行数据库备份操作
     * @param rawDbNames 原始数据库名称输入
     * @return 备份执行结果
     */
    String executeBackup(String rawDbNames) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c",
                MYSQL_DUMP_PATH + " " + formatDatabaseNames(rawDbNames));
            Process process = pb.start();
            return IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "Backup failed: " + e.getMessage();
        }
    }

    /**
     * 格式化数据库名称参数
     * @param input 用户输入
     * @return 格式化后的参数字符串
     */
    private String formatDatabaseNames(String input) {
        return "--databases " + filterDatabaseNames(input).replace(",", " ");
    }

    /**
     * 过滤数据库名称中的特殊字符
     * @param input 用户输入
     * @return 过滤后的字符串
     */
    private String filterDatabaseNames(String input) {
        // 保留字母数字和逗号，替换其他字符为空
        return input.replaceAll("[^a-zA-Z0-9,]", "");
    }
}