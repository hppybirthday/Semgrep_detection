package com.example.mlapp.model;

import java.nio.file.Path;
import java.nio.file.Paths;

public class ModelExporter {
    public void exportModel(String outputDir) {
        // 构建模型导出路径并配置日志
        String targetPath = FileUtil.buildModelPath(outputDir);
        LoggerConfig.configureLogging(targetPath);
        // 模拟模型文件持久化操作
        FileUtil.saveModelFile(targetPath + "/model.dat");
    }
}

class FileUtil {
    public static String buildModelPath(String userDir) {
        // 将用户输入与基础目录拼接并规范化
        return Paths.get("/var/models/").resolve(userDir).normalize().toString();
    }

    public static void saveModelFile(String path) {
        // 实际文件写入逻辑（模拟）
        // 通过日志框架间接触发文件操作
        LoggerConfig.logOperation("Model saved to: " + path);
    }
}

class LoggerConfig {
    // 模拟日志框架配置接口
    public static void configureLogging(String logPath) {
        // 通过反射调用日志框架API设置日志路径
        // 实际使用log4j/slf4j等框架的配置方法
        System.setProperty("log.file.path", logPath);
    }

    public static void logOperation(String message) {
        // 模拟日志记录行为
        System.out.println("[INFO] " + message);
    }
}