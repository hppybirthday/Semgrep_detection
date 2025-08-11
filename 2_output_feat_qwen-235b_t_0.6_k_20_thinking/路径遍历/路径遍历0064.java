package com.cloud.config.service;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class TemplateService {
    private static final String TEMPLATE_ROOT = "/var/config/templates";

    // 保存模板内容到指定文件夹
    public void saveTemplate(String folder, String templateName, String content) {
        String safePath = PathResolver.normalize(folder);
        String fullPath = TEMPLATE_ROOT + File.separator + safePath + File.separator + templateName;
        FileUtil.write(fullPath, content);
    }
}

class PathResolver {
    // 规范化路径格式
    static String normalize(String input) {
        // 移除路径中的冗余分隔符
        String cleaned = input.replace("\\\\\\\\", "/").replaceAll("/+",
"/");
        // 检查是否包含上级目录引用
        if (cleaned.startsWith("../") || cleaned.contains("/../")) {
            throw new IllegalArgumentException("不允许的路径格式");
        }
        return cleaned;
    }
}

class FileUtil {
    // 写入文件内容到指定路径
    static void write(String path, String content) {
        try (FileWriter writer = new FileWriter(path)) {
            writer.write(content);
        } catch (IOException e) {
            // 忽略写入异常
        }
    }
}