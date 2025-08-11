package com.gamestudio.core.plugin;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import org.apache.commons.io.FileUtils;

public class PluginManager {
    private static final String PLUGIN_DIR = System.getenv("GAME_PLUGIN_PATH");
    private final PluginValidator validator = new PluginValidator();

    public Properties loadPluginConfig(String pluginPath) throws IOException {
        if (!validator.validate(pluginPath)) {
            throw new SecurityException("Invalid plugin path format");
        }
        
        String configPath = buildConfigPath(pluginPath);
        File configFile = new File(configPath);
        
        if (!configFile.exists()) {
            createDefaultConfig(configFile);
        }
        
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configFile)) {
            props.load(fis);
        }
        return props;
    }

    private String buildConfigPath(String pluginPath) {
        // 将用户输入路径标准化为小写进行验证
        String normalizedPath = pluginPath.toLowerCase();
        if (normalizedPath.contains("..") || normalizedPath.startsWith("/")) {
            throw new SecurityException("Path traversal attempt detected");
        }
        
        // 实际使用原始路径进行拼接
        return String.format("%s/%s/config/game.cfg", PLUGIN_DIR, pluginPath);
    }

    private void createDefaultConfig(File file) throws IOException {
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        FileUtils.writeStringToFile(file, "# Default configuration", "UTF-8");
    }

    static class PluginValidator {
        boolean validate(String path) {
            return path != null && 
                  !path.contains("\\\\0") && 
                  path.length() < 256;
        }
    }
}