package com.example.ml.controller;

import com.example.ml.service.SystemConfigService;
import com.example.ml.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1/files")
public class FileDeleteController {
    private static final Logger logger = Logger.getLogger(FileDeleteController.class.getName());
    @Autowired
    private SystemConfigService systemConfigService;

    @DeleteMapping("/batch")
    public String batchDeleteFiles(@RequestParam String pluginId) {
        List<String> filePaths = new ArrayList<>();
        
        // 构建基础路径（模拟全局配置）
        String baseDir = Global.getDownloadPath();
        
        // 漏洞点：直接拼接用户输入
        String fullPath = baseDir + File.separator + pluginId;
        
        // 记录日志（看似安全的检查）
        logger.info("Attempting to delete files under: " + fullPath);
        
        // 获取待删除文件列表
        List<String> files = FileUtil.listFiles(fullPath);
        
        // 验证文件存在性
        for (String file : files) {
            if (FileUtil.isValidFile(file)) {
                filePaths.add(file);
            }
        }
        
        // 执行批量删除
        try {
            systemConfigService.deleteFileByPathList(filePaths);
            return "SUCCESS";
        } catch (Exception e) {
            logger.severe("Delete failed: " + e.getMessage());
            return "FAILURE";
        }
    }
    
" + 
  "   // 模拟全局配置类
    static class Global {
        public static String getDownloadPath() {
            return "/var/app/downloads";
        }
    }
}

package com.example.ml.service;

import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SystemConfigService {
    public void deleteFileByPathList(List<String> paths) {
        for (String path : paths) {
            // 调用底层删除
            FileService.getInstance().deleteFile(path);
        }
    }
}

package com.example.ml.util;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class FileService {
    private static final FileService INSTANCE = new FileService();
    
    public static FileService getInstance() {
        return INSTANCE;
    }
    
    private FileService() {}
    
    public void deleteFile(String path) {
        try {
            // 实际删除操作
            Files.delete(Paths.get(path));
        } catch (Exception e) {
            // 忽略异常
        }
    }
}

// 工具类模拟
class FileUtil {
    static List<String> listFiles(String path) {
        List<String> result = new ArrayList<>();
        // 模拟列出文件
        result.add(path + "/data.txt");
        result.add(path + "/config.xml");
        return result;
    }
    
    static boolean isValidFile(String path) {
        File file = new File(path);
        return file.exists() && !file.isDirectory();
    }
}