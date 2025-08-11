package com.example.secureapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.secureapp.service.FileDeletionService;

@RestController
public class FileDeletionController {
    @Autowired
    private FileDeletionService fileDeletionService;

    // 处理文件删除请求
    @PostMapping("/delete")
    public String handleDelete(@RequestParam("path") String path) {
        try {
            // 调用文件删除服务
            fileDeletionService.deleteUserFile(path);
            return "文件删除成功";
        } catch (Exception e) {
            return "文件删除失败: " + e.getMessage();
        }
    }
}

package com.example.secureapp.service;

import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.example.secureapp.util.FileUtil;

@Service
public class FileDeletionService {
    @Value("${storage.base-path}")
    private String baseStoragePath;

    // 删除用户指定文件
    public void deleteUserFile(String relativePath) {
        // 构造完整文件路径（存在漏洞）
        String fullPath = Paths.get(baseStoragePath, relativePath).toString();
        
        // 执行文件删除操作
        FileUtil.deleteFile(fullPath);
    }
}

package com.example.secureapp.util;

import java.io.File;

public class FileUtil {
    // 安全删除指定路径的文件
    public static void deleteFile(String filePath) {
        File file = new File(filePath);
        
        // 检查文件是否存在
        if (file.exists()) {
            // 删除文件操作
            file.delete();
        }
    }
}