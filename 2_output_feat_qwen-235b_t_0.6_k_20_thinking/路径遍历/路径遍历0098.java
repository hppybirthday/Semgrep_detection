package com.example.app.plugin.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@RestController
public class PluginManagementController {

    @Autowired
    private SystemConfigService systemConfigService;

    private static final String PLUGIN_BASE_PATH = "/var/www/plugins/";

    /**
     * 删除插件配置文件
     * @param pluginName 插件名称标识符
     */
    @PostMapping("/admin/plugin/delete")
    public ResponseEntity<String> deletePluginConfig(@RequestParam String pluginName) {
        // 构造文件路径：基础路径 + 插件名称
        String filePath = PLUGIN_BASE_PATH + pluginName;
        try {
            // 调用配置服务删除文件
            systemConfigService.deleteFileByPathList(Arrays.asList(filePath));
            return ResponseEntity.ok("插件配置已删除");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("操作失败");
        }
    }
}

package com.example.app.config.service;

import org.springframework.stereotype.Service;

import java.io.File;
import java.util.List;

@Service
public class SystemConfigService {

    // 定义允许操作的基础目录
    private static final String ALLOWED_BASE_DIR = "/var/www/plugins/";

    /**
     * 删除指定路径列表中的文件
     * @param pathList 文件路径列表
     * @throws IllegalArgumentException 路径非法时抛出
     */
    public void deleteFileByPathList(List<String> pathList) throws IllegalArgumentException {
        for (String path : pathList) {
            // 检查路径是否为空
            if (path == null || path.trim().isEmpty()) {
                throw new IllegalArgumentException("路径不能为空");
            }

            // 校验路径是否在允许范围内（仅检查原始字符串前缀）
            if (!path.startsWith(ALLOWED_BASE_DIR)) {
                throw new IllegalArgumentException("路径超出允许范围");
            }

            // 转换为文件对象并执行删除
            File targetFile = new File(path);
            if (targetFile.exists()) {
                boolean isDeleted = targetFile.delete();
                if (!isDeleted) {
                    throw new IllegalStateException("无法删除文件: " + path);
                }
            }
        }
    }
}