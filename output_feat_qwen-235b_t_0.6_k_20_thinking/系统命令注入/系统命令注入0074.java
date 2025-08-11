import java.io.*;
import java.net.*;
import java.util.*;

class DataCleaner {
    // 模拟数据库备份命令执行
    public static void executeBackup(String dbUser, String dbPass, String dbName) {
        try {
            // 漏洞点：直接拼接用户输入到命令中
            String cmd = "mysqldump -u" + dbUser + " -p" + dbPass + " " + dbName + " > /backup/" + dbName + ".sql";
            System.out.println("执行命令: " + cmd);
            
            // 使用Runtime执行命令（Unix环境）
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            
            // 读取命令执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("输出: " + line);
            }
            while ((line = errorReader.readLine()) != null) {
                System.err.println("错误: " + line);
            }
            
            process.waitFor();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

public class VulnerableDataProcessor {
    // 模拟HTTP请求处理
    public static void handleRequest(String query) {
        try {
            // 解析查询参数
            Map<String, String> params = new HashMap<>();
            for (String param : query.split("&")) {
                String[] parts = param.split("=");
                if (parts.length == 2) {
                    params.put(parts[0], URLDecoder.decode(parts[1], "UTF-8"));
                }
            }
            
            // 获取用户输入的数据库参数（存在漏洞的输入处理）
            String dbUser = params.getOrDefault("user", "root");
            String dbPass = params.getOrDefault("pass", "defaultpass");
            String dbName = params.getOrDefault("db", "maindb");
            
            // 错误的防御尝试（绕过示例）
            if (dbName.contains(";")) {
                dbName = dbName.replace(";", "\\;" ); // 错误的转义方式
            }
            
            // 执行存在漏洞的命令
            DataCleaner.executeBackup(dbUser, dbPass, dbName);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // 模拟主程序入口
    public static void main(String[] args) {
        try {
            // 模拟HTTP请求处理（GET参数注入）
            // 示例请求: /dataclean?user=admin&pass=123456&db=maindb;rm%20-rf%20/
            String rawQuery = "user=admin&pass=123456&db=maindb;rm%20-rf%20/";
            System.out.println("处理请求参数: " + rawQuery);
            handleRequest(rawQuery);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}