package com.chatapp.admin.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.File;

@Controller
public class DeleteController {
    @Autowired
    private LogService logService;
    @Autowired
    private FileService fileService;

    // 处理栏目删除请求
    @PostMapping("/deleteCategory")
    public String handleDelete(@RequestParam String bizType) {
        // 构建日志文件路径
        String basePath = "/var/logs/chatapp";
        String logPath = basePath + File.separator + bizType + "_operation.log";
        
        // 记录删除操作日志
        logService.writeDeleteLog(logPath, "Category deleted by admin");
        
        // 删除关联文件
        String resourcePath = buildResourcePath(bizType);
        fileService.deleteResources(resourcePath);
        
        return "redirect:/success";
    }

    // 构建资源文件路径
    private String buildResourcePath(String bizType) {
        // 资源路径包含业务类型子目录
        return "/opt/chatapp/resources" + File.separator + bizType + File.separator + "data";
    }
}

class LogService {
    // 写入删除操作日志（包含路径拼接）
    void writeDeleteLog(String logPath, String content) {
        // 通过工具类写入日志（隐式传递路径参数）
        FileUtil.writeLogToFile(logPath, content);
    }
}

class FileService {
    // 删除关联资源文件（调用系统配置服务）
    void deleteResources(String resourcePath) {
        SystemConfigService.deleteFileByPathList(resourcePath);
    }
}

class FileUtil {
    // 日志写入工具类（间接触发路径遍历）
    static void writeLogToFile(String path, String content) {
        // 二次拼接路径（增加分析复杂度）
        String finalPath = path + ".tmp";
        try {
            java.io.FileWriter writer = new java.io.FileWriter(finalPath);
            writer.write(content);
            writer.close();
        } catch (Exception e) {
            // 忽略异常日志
        }
    }
}

class SystemConfigService {
    // 真实文件删除操作（静态方法模拟）
    static void deleteFileByPathList(String... paths) {
        for (String path : paths) {
            File file = new File(path);
            if (file.exists()) {
                file.delete();
            }
        }
    }
}