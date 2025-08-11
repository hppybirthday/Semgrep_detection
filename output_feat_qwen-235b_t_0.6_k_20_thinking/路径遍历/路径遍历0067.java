package com.example.taskmanager.domain;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

// 领域实体
public class TaskCategory {
    private String id;
    private String name;
    private String bizPath; // 业务路径字段

    // 领域服务
    public static class CategoryService {
        private final FileStorageUtil fileStorage;
        private static final String BASE_DIR = "/var/taskdata/";

        public CategoryService() {
            this.fileStorage = new FileStorageUtil();
        }

        public boolean addCategory(TaskCategory category) {
            try {
                // 漏洞点：直接拼接用户输入路径
                String fullPath = BASE_DIR + category.getBizPath();
                fileStorage.createDirectory(fullPath);

                // 生成配置文件时再次使用未验证路径
                GenerateUtil.generateFile(fullPath, "config.json", "{}", true);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
    }

    // 基础设施层
    static class FileStorageUtil {
        public void createDirectory(String path) {
            new File(path).mkdirs();
        }
    }

    // 漏洞核心触发类
    static class GenerateUtil {
        public static void generateFile(String basePath, String relativePath, String content, boolean overwrite) throws IOException {
            // 路径拼接漏洞：未进行路径规范化处理
            File targetFile = new File(basePath, relativePath);
            
            if (!targetFile.getParentFile().exists()) {
                targetFile.getParentFile().mkdirs();
            }

            if (targetFile.exists() && !overwrite) {
                throw new IOException("File already exists");
            }

            try (FileWriter writer = new FileWriter(targetFile)) {
                writer.write(content);
            }
        }
    }

    // Getters & Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getBizPath() { return bizPath; }
    public void setBizPath(String bizPath) { this.bizPath = bizPath; }
}