package com.task.manager.controller;

import com.task.manager.service.PluginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/plugins")
public class PluginController {
    @Autowired
    private PluginService pluginService;

    @GetMapping(path = "/{pluginId}/config", produces = MediaType.TEXT_PLAIN_VALUE)
    public void downloadConfig(@PathVariable String pluginId, HttpServletResponse response) throws IOException {
        // 获取插件配置内容
        String configContent = pluginService.readConfig(pluginId);
        
        // 设置响应头
        response.setHeader("Content-Disposition", "inline; filename=\\"config.txt\\"");
        response.getWriter().write(configContent);
    }
}

// Service层
package com.task.manager.service;

import com.task.manager.util.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;

@Service
public class PluginService {
    @Value("${plugin.config.dir}")
    private String configBaseDir;

    public String readConfig(String pluginId) throws IOException {
        // 校验参数非空（防御性编程）
        if (pluginId == null || pluginId.isEmpty()) {
            throw new IllegalArgumentException("插件ID不能为空");
        }
        
        // 构建配置文件路径（漏洞点：未规范化路径）
        File configDir = new File(configBaseDir);
        File targetFile = new File(configDir, pluginId + "/config.txt");
        
        // 读取文件内容
        return FileUtils.readFileToString(targetFile, "UTF-8");
    }
}

// 工具类
package com.task.manager.util;

import org.apache.commons.io.FileUtils;
import org.springframework.lang.Nullable;

import java.io.File;
import java.io.IOException;

public class FileUtils {
    public static String readFileToString(File file, String encoding) throws IOException {
        // 使用Apache Commons IO进行文件读取
        return FileUtils.readFileToString(file, encoding);
    }
}