package com.gamestudio.modloader;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

public class ModDownloadController {
    private static final String MOD_STORAGE = "plugins/configs/";
    private final ModService modService = new ModService();

    public void handleDownload(String modId, String targetPath) {
        try {
            String normalizedPath = FileUtil.normalizePath(targetPath);
            if (!isValidPath(normalizedPath)) {
                throw new SecurityException("Invalid path");
            }
            
            Properties modConfig = modService.loadModConfig(modId);
            String content = modConfig.getProperty("content");
            
            FileUtil.saveContentToFile(content, MOD_STORAGE + modId + ".yaml");
            System.out.println("Mod downloaded successfully");
        } catch (Exception e) {
            System.err.println("Download failed: " + e.getMessage());
        }
    }

    private boolean isValidPath(String path) {
        return path.startsWith(MOD_STORAGE) && 
              !path.contains("..") && 
              path.length() < 256;
    }

    public static void main(String[] args) {
        ModDownloadController controller = new ModDownloadController();
        // 恶意输入示例
        controller.handleDownload("../../etc/passwd", "download");
    }
}

class ModService {
    public Properties loadModConfig(String modId) throws IOException {
        Path configPath = Paths.get("plugins/configs/", modId + ".yaml");
        Properties props = new Properties();
        
        if (Files.exists(configPath)) {
            try (FileInputStream fis = new FileInputStream(configPath.toFile())) {
                props.load(fis);
            }
        } else {
            props.setProperty("content", "default_mod_content");
            saveDefaultConfig(configPath, props);
        }
        return props;
    }

    private void saveDefaultConfig(Path configPath, Properties props) {
        try {
            Files.createDirectories(configPath.getParent());
            try (FileOutputStream fos = new FileOutputStream(configPath.toFile())) {
                props.store(fos, "Default mod config");
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to save config: " + e.getMessage());
        }
    }
}

class FileUtil {
    public static String normalizePath(String path) {
        return path.replace("\\\\", "/").toLowerCase();
    }

    public static void saveContentToFile(String content, String filePath) {
        try {
            Path path = Paths.get(filePath);
            Files.createDirectories(path.getParent());
            try (FileOutputStream fos = new FileOutputStream(path.toFile())) {
                fos.write(content.getBytes());
            }
        } catch (IOException e) {
            throw new RuntimeException("File write error: " + e.getMessage());
        }
    }
}