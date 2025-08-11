package com.example.mathmodeller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * 数学模型加载器基类
 * 支持从不同来源加载模型配置
 */
public abstract class ModelLoader {
    protected final String baseDirectory;

    public ModelLoader(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    public abstract Properties loadModel(String modelName) throws IOException;
}

/**
 * 文件系统模型加载器
 * 从本地文件系统加载模型配置
 */
public class FileSystemModelLoader extends ModelLoader {
    public FileSystemModelLoader(String baseDirectory) {
        super(baseDirectory);
    }

    @Override
    public Properties loadModel(String modelName) throws IOException {
        // 漏洞点：直接拼接用户输入到文件路径
        String modelPath = getModelPath(modelName);
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(modelPath)) {
            props.load(fis);
        }
        return props;
    }

    private String getModelPath(String modelName) {
        // 漏洞点：不安全的路径拼接
        Path path = Paths.get(baseDirectory, "models", modelName);
        return path.toString();
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java FileSystemModelLoader <model-name>");
            return;
        }

        try {
            // 创建加载器实例
            ModelLoader loader = new FileSystemModelLoader("/opt/math_models");
            
            // 加载模型配置
            Properties config = loader.loadModel(args[0]);
            
            // 输出加载的配置
            System.out.println("Loaded configuration:");
            config.forEach((k, v) -> System.out.println(k + ": " + v));
            
        } catch (IOException e) {
            System.err.println("Error loading model: " + e.getMessage());
            e.printStackTrace();
        }
    }
}