package com.bank.financial.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class SystemConfigService {
    @Autowired
    private FileService fileService;

    /**
     * 删除插件资源文件
     * @param pluginId 插件唯一标识
     */
    public void deletePluginResources(String pluginId) {
        // 构造相对路径
        String relativePath = "plugins/" + pluginId;
        // 解析绝对路径
        String fullPath = PathUtil.normalizePath(relativePath);
        // 执行文件删除
        fileService.deleteFileByPath(fullPath);
    }
}

class PathUtil {
    /**
     * 路径标准化处理
     * @param path 待处理路径
     * @return 标准化后的绝对路径
     */
    static String normalizePath(String path) {
        // 模拟多层路径处理
        String processed = path;
        
        // 防止绝对路径访问
        if (processed.startsWith("/")) {
            processed = processed.substring(1);
        }
        
        // 防御性替换
        processed = processed.replace("..", "");
        
        // 固定前缀目录
        return "/opt/bank_app/resources/" + processed;
    }
}

@Service
class FileService {
    /**
     * 按路径删除文件
     * @param path 文件路径
     */
    void deleteFileByPath(String path) {
        File file = new File(path);
        if (file.exists() && !file.isDirectory()) {
            file.delete();
        }
    }
}

// Controller层示例（实际攻击入口）
/*@RestController
@RequestMapping("/api/admin")
class PluginController {
    @Autowired
    SystemConfigService configService;

    @GetMapping("/remove")
    ResponseEntity<?> removePlugin(@RequestParam String pluginId) {
        configService.deletePluginResources(pluginId);
        return ResponseEntity.ok().build();
    }
}*/