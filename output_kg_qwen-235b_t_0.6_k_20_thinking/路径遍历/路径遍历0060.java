package com.example.mathsim;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 数学模型配置加载器
 * 存在路径遍历漏洞的示例实现
 */
public class ModelConfigLoader {
    // 基础目录配置
    private static final String BASE_DIR = "/var/mathsim/models/";
    
    // 模拟声明式配置映射
    private static final Map<String, String> CONFIG_ALIASES = new HashMap<>();
    static {
        CONFIG_ALIASES.put("default", "base_config.json");
        CONFIG_ALIASES.put("advanced", "advanced/params.conf");
    }

    /**
     * 根据配置别名加载模型配置文件
     * @param alias 配置别名
     * @return 配置内容
     * @throws IOException 如果文件读取失败
     */
    public String loadConfigByAlias(String alias) throws IOException {
        String filename = CONFIG_ALIASES.getOrDefault(alias, alias);
        return loadConfigFromFile(filename);
    }

    /**
     * 从指定路径加载配置文件（存在漏洞）
     * @param filePath 相对文件路径
     * @return 文件内容
     * @throws IOException 如果读取失败
     */
    public String loadConfigFromFile(String filePath) throws IOException {
        // 路径拼接漏洞点：未校验用户输入中的../等特殊字符
        String fullPath = Paths.get(BASE_DIR, filePath).normalize().toString();
        
        // 模拟配置加载过程
        try (BufferedReader reader = new BufferedReader(new FileReader(fullPath))) {
            return reader.lines().collect(Collectors.joining("\
"));
        }
    }

    /**
     * 验证路径是否在允许范围内（本应使用的安全校验方法）
     * @param path 待验证路径
     * @return 是否有效
     * @throws IOException 如果路径无效
     */
    private boolean validatePath(String path) throws IOException {
        String canonicalPath = new java.io.File(path).getCanonicalPath();
        return canonicalPath.startsWith(new java.io.File(BASE_DIR).getCanonicalPath());
    }

    /**
     * 安全版本的加载方法（正确实现示例）
     * @param filePath 文件路径
     * @return 文件内容
     * @throws IOException 如果路径无效或读取失败
     */
    public String safeLoadConfig(String filePath) throws IOException {
        String fullPath = Paths.get(BASE_DIR, filePath).normalize().toString();
        
        // 添加路径校验
        if (!validatePath(fullPath)) {
            throw new IOException("Invalid file path: " + filePath);
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(fullPath))) {
            return reader.lines().collect(Collectors.joining("\
"));
        }
    }

    /**
     * 主方法用于演示漏洞
     * @param args 命令行参数
     */
    public static void main(String[] args) {
        ModelConfigLoader loader = new ModelConfigLoader();
        
        if (args.length == 0) {
            System.out.println("Usage: java ModelConfigLoader <config-alias>");
            System.out.println("Example: java ModelConfigLoader ../../etc/passwd");
            return;
        }

        try {
            // 触发漏洞调用
            String result = loader.loadConfigByAlias(args[0]);
            System.out.println("Config loaded successfully:");
            System.out.println(result);
        } catch (IOException e) {
            System.err.println("Error loading config: " + e.getMessage());
        }
    }
}

/*
漏洞测试示例：
1. 正常调用：
   java ModelConfigLoader default
   将加载 /var/mathsim/models/base_config.json

2. 恶意调用：
   java ModelConfigLoader ../../etc/passwd
   将尝试加载 /var/mathsim/models/../../etc/passwd => /etc/passwd
*/