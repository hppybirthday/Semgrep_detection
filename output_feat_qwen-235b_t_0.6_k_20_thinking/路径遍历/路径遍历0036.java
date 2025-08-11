package com.example.demo.controller;

import com.example.demo.service.SystemConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;

@RestController
@RequestMapping("/api/files")
public class FileUploadController {
    
    @Autowired
    private SystemConfigService systemConfigService;
    
    private String baseDir = "/var/www/uploads/";
    
    @DeleteMapping("/delete")
    public String deleteFile(@RequestParam String prefix, @RequestParam String suffix) {
        try {
            // 模拟生成日期目录和UUID
            String dateDir = new SimpleDateFormat("yyyy/MM/dd").format(new Date());
            String uuid = UUID.randomUUID().toString();
            
            // 漏洞点：直接拼接用户输入到路径中
            String finalPath = baseDir + dateDir + "/" + prefix + uuid + suffix;
            
            File fileToDelete = new File(finalPath);
            
            // 记录删除操作（模拟审计日志）
            System.out.println("[AUDIT] Attempting to delete: " + finalPath);
            
            // 调用存在漏洞的服务方法
            systemConfigService.deleteFileByPathList(java.util.Collections.singletonList(finalPath));
            
            return "File deleted successfully";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error deleting file: " + e.getMessage();
        }
    }
}

// 模拟服务层实现
package com.example.demo.service;

import java.util.List;

public class SystemConfigService {
    public void deleteFileByPathList(List<String> paths) {
        paths.forEach(path -> {
            try {
                // 漏洞：直接使用未经验证的路径
                File file = new File(path);
                if (file.exists()) {
                    file.delete();
                    System.out.println("Deleted file: " + path);
                } else {
                    System.out.println("File not found: " + path);
                }
            } catch (Exception e) {
                System.err.println("Error deleting file: " + path + ", " + e.getMessage());
            }
        });
    }
}