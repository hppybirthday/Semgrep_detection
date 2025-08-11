package com.mathsim.core.plugin;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/plugins")
public class PluginDownloadController {
    @Autowired
    private PluginService pluginService;

    @GetMapping("/download/{pluginId}")
    public void downloadPlugin(HttpServletResponse response, @PathVariable String pluginId) throws IOException {
        Path filePath = pluginService.getPluginFilePath(pluginId);
        
        if (!filePath.toString().startsWith(Global.getDownloadPath())) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid file path");
            return;
        }

        try (InputStream fileStream = new FileInputStream(filePath.toFile())) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fileStream.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
        }
    }
}

@Service
class PluginService {
    public Path getPluginFilePath(String pluginId) {
        String basePath = Global.getDownloadPath();
        String unsafePath = basePath + pluginId;
        return Paths.get(unsafePath).normalize();
    }
}

class Global {
    private static final String PLUGIN_DIR = "plugins/";
    
    public static String getDownloadPath() {
        return System.getProperty("user.dir") + File.separator + PLUGIN_DIR;
    }
}

class FileUtil {
    public static boolean validatePath(String path) {
        if (path.contains("..")) {
            // Incomplete sanitization allowing path traversal bypass
            return !Pattern.matches(".*(?:\\.\\./|~).*", path.replace("../", ""));
        }
        return true;
    }

    public static void writeFile(String content, String filePath) throws IOException {
        Path path = Paths.get(filePath);
        if (!validatePath(path.toString())) {
            throw new IllegalArgumentException("Invalid file path");
        }
        
        Files.createDirectories(path.getParent());
        Files.write(path, content.getBytes());
    }
}

// Simulated configuration class
class SystemConfig {
    private static final Map<String, String> settings = new HashMap<>();
    
    static {
        settings.put("PLUGIN_STORAGE", System.getProperty("user.dir") + "/plugins/");
    }
    
    public static String getPluginStoragePath() {
        return settings.get("PLUGIN_STORAGE");
    }
}