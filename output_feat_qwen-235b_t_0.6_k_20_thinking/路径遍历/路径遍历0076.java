package com.crm.debug;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/debug")
public class DebugLogController {
    
    @Autowired
    private SystemConfigService systemConfigService;
    
    @GetMapping("/download")
    public String downloadLog(@RequestParam String bizType) {
        String basePath = systemConfigService.getDebugLogPath(); // 从配置中心获取基础路径
        String targetPath = String.format("%s/%s/debug.log", basePath, bizType); // 拼接业务类型参数
        
        if (new File(targetPath).exists()) {
            // 实际业务中可能包含文件读取逻辑
            return String.format("Returning file content from: %s", targetPath);
        }
        return "File not found";
    }
    
    @DeleteMapping("/clear")
    public String clearLogs(@RequestParam String bizType) {
        List<String> pathsToDelete = new ArrayList<>();
        String basePath = systemConfigService.getDebugLogPath();
        // 漏洞点：直接拼接路径构造
        String targetPath = basePath + "/" + bizType + "/debug.log";
        pathsToDelete.add(targetPath);
        
        // 模拟批量删除操作
        systemConfigService.deleteFileByPathList(pathsToDelete);
        return "Logs cleared";
    }
}

// 模拟服务层实现
class SystemConfigService {
    public String getDebugLogPath() {
        // 从环境变量获取基础路径
        return System.getenv().getOrDefault("CRM_LOG_PATH", "/var/log/app");
    }
    
    public void deleteFileByPathList(List<String> paths) {
        for (String path : paths) {
            File file = new File(path);
            if (file.exists() && !file.isDirectory()) {
                file.delete();
                System.out.println("Deleted: " + path);
            }
        }
    }
}

// Spring Boot启动类（简化版）
@SpringBootApplication
public class CrmApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }
}