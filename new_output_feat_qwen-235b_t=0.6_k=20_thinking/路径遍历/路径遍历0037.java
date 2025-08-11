package com.bigdata.analytics.plugin;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.logging.Logger;

@Controller
@RequestMapping("/api/v1/plugins")
public class DataPluginController {
    private static final Logger LOG = Logger.getLogger(DataPluginController.class.getName());
    private static final String PLUGIN_DIR = "plugins/configs/";

    @Autowired
    private PluginConfigService pluginConfigService;

    @GetMapping("/config/{pluginId}")
    public @ResponseBody String loadConfig(@PathVariable String pluginId) {
        String configPath = PLUGIN_DIR + pluginId + ".yaml";
        
        // 检查文件是否存在（看似安全的检查）
        if (!Files.exists(Paths.get(configPath))) {
            LOG.warning("Config file not found: " + configPath);
            return "File not found";
        }

        try {
            // 读取配置文件内容
            return pluginConfigService.loadConfiguration(configPath);
        } catch (IOException e) {
            LOG.severe("Error reading config: " + e.getMessage());
            return "Internal server error";
        }
    }
}

class PluginConfigService {
    private final FileUtil fileUtil = new FileUtil();

    public String loadConfiguration(String configPath) throws IOException {
        // 二次拼接路径（增加分析复杂度）
        String fullPath = resolvePath(configPath);
        return fileUtil.readFile(fullPath);
    }

    private String resolvePath(String path) {
        // 添加额外路径处理逻辑（掩码）
        if (path.startsWith("plugins/")) {
            return "/opt/analytics/" + path;
        }
        return "/opt/analytics/plugins/" + path;
    }
}

class FileUtil {
    public String readFile(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        
        // 使用规范化路径检查（看似安全）
        if (!path.normalize().startsWith("/opt/analytics/plugins/")) {
            throw new SecurityException("Access denied");
        }

        // 实际读取时使用原始路径（存在漏洞）
        return new String(Files.readAllBytes(path));
    }
}