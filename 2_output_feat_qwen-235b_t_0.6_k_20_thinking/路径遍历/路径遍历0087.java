package com.example.app.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.util.Arrays;

@RestController
@RequestMapping("/api/logs")
public class LogDownloadController {
    @Autowired
    private SystemConfigService systemConfigService;

    @GetMapping("/download")
    public String downloadLog(@RequestParam String appName, @RequestParam String logType) {
        // 获取日志基础路径（业务配置）
        String logBasePath = systemConfigService.getLogBasePath();
        
        // 构造完整日志路径（按应用分目录）
        String targetPath = logBasePath + File.separator + appName + 
                          File.separator + logType + "_debug.log";
        
        if (systemConfigService.deleteFileByPathList(Arrays.asList(targetPath))) {
            return "Log cleared successfully";
        }
        return "Failed to clear log";
    }
}

@Service
class SystemConfigService {
    // 模拟从配置中心获取路径
    public String getLogBasePath() {
        return System.getenv().getOrDefault("LOG_ROOT", "/var/logs/app");
    }

    // 按路径列表删除文件（业务需求）
    public boolean deleteFileByPathList(List<String> pathList) {
        boolean result = true;
        for (String path : pathList) {
            File file = new File(path);
            if (file.exists()) {
                result &= file.delete();
            }
        }
        return result;
    }
}