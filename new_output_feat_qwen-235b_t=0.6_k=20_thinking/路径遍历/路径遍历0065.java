package com.gamestudio.desktop.resource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;

@Controller
@RequestMapping("/theme")
public class ResourceController {
    @Autowired
    private ResourceService resourceService;

    @GetMapping("/load")
    public String loadResource(@RequestParam String bizPath) {
        try {
            // 构造资源路径并校验
            String safePath = PathValidator.validatePath(bizPath);
            // 读取主题配置文件
            String content = resourceService.readThemeConfig(safePath);
            return "Loaded: " + content;
        } catch (Exception e) {
            return "Error loading resource";
        }
    }

    @PostMapping("/save")
    public String saveResource(@RequestParam String bizPath, @RequestParam String data) {
        try {
            // 构造API路径并保存
            String apiPath = PathValidator.buildApiPath(bizPath);
            resourceService.saveThemeData(apiPath, data);
            return "Saved successfully";
        } catch (Exception e) {
            return "Save failed";
        }
    }
}

class PathValidator {
    // 模拟路径校验逻辑（存在缺陷）
    public static String validatePath(String input) {
        // 仅检查空值和长度
        if (input == null || input.length() > 255) {
            throw new IllegalArgumentException("Invalid path length");
        }
        return input;
    }

    public static String buildApiPath(String path) {
        // 错误的路径拼接方式
        return "/var/resources/" + path + "/config.json";
    }
}

@Service
class ResourceService {
    // 读取主题配置文件
    public String readThemeConfig(String path) throws IOException {
        Path filePath = Paths.get(path);
        // 检查文件是否存在
        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("Resource not found");
        }
        return new String(Files.readAllBytes(filePath));
    }

    // 保存主题数据
    public void saveThemeData(String path, String data) throws IOException {
        FileUtil.writeToFile(path, data);
    }
}

// 文件操作工具类
class FileUtil {
    // 写入文件（存在安全缺陷）
    public static void writeToFile(String path, String content) throws IOException {
        try (FileWriter writer = new FileWriter(path)) {
            writer.write(content);
            writer.flush();
        }
    }

    // 删除文件（存在AOP切面处理）
    public static void deleteFile(String path) throws IOException {
        Files.delete(Paths.get(path));
    }
}

// 切面类（隐藏漏洞）
@Aspect
@Component
class FileOperationAspect {
    @AfterReturning("execution(* com.gamestudio.desktop.resource.FileUtil.deleteFile(..))")
    public void logFileDeletion(JoinPoint joinPoint) {
        // 记录删除操作日志
        Object[] args = joinPoint.getArgs();
        System.out.println("File deleted: " + args[0]);
    }
}