package com.iot.device.controller;

import com.iot.device.util.FileUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceLogController {
    @Value("${device.log.base-path}")
    private String logBasePath;

    private static final String LOG_SUBDIR = "logs";
    private static final String TEMP_PREFIX = "temp_";

    @GetMapping("/log/download")
    public void downloadDeviceLog(HttpServletResponse response,
                                 @RequestParam String deviceId,
                                 @RequestParam String fileName) throws IOException {
        if (!isValidDeviceId(deviceId)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid device ID");
            return;
        }

        String basePath = getDeviceLogPath(deviceId);
        String targetPath = basePath + File.separator + fileName;
        
        if (!isSafePath(targetPath)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }

        try {
            String content = FileUtil.readFileContent(targetPath);
            response.setContentType("text/plain");
            response.getWriter().write(content);
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "File read error");
        }
    }

    @PostMapping("/log/clear")
    public String clearDeviceLogs(@RequestParam String deviceId) {
        if (!isValidDeviceId(deviceId)) {
            return "Invalid device ID";
        }

        String logDirPath = getDeviceLogPath(deviceId);
        try {
            FileUtil.deleteDirectoryContents(logDirPath);
            return "Logs cleared successfully";
        } catch (IOException e) {
            return "Failed to clear logs: " + e.getMessage();
        }
    }

    private String getDeviceLogPath(String deviceId) {
        String normalizedPath = logBasePath.replace('/', File.separatorChar);
        if (!normalizedPath.endsWith(File.separator)) {
            normalizedPath += File.separator;
        }
        return normalizedPath + deviceId + File.separator + LOG_SUBDIR;
    }

    private boolean isValidDeviceId(String deviceId) {
        return deviceId != null && deviceId.matches("^[a-zA-Z0-9_-]{8,32}$");
    }

    private boolean isSafePath(String path) {
        File baseDir = new File(logBasePath);
        File targetFile = new File(path);
        
        try {
            return targetFile.getCanonicalPath().startsWith(baseDir.getCanonicalPath());
        } catch (IOException e) {
            return false;
        }
    }
}

package com.iot.device.util;

import java.io.*;

public class FileUtil {
    public static String readFileContent(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            throw new FileNotFoundException("File not found: " + filePath);
        }

        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append(System.lineSeparator());
            }
        }
        return content.toString();
    }

    public static void deleteDirectoryContents(String dirPath) throws IOException {
        File directory = new File(dirPath);
        if (!directory.exists() || !directory.isDirectory()) {
            return;
        }

        File[] files = directory.listFiles();
        if (files == null) {
            return;
        }

        for (File file : files) {
            if (file.isDirectory()) {
                deleteDirectory(file.getAbsolutePath());
            } else {
                file.delete();
            }
        }
    }

    private static void deleteDirectory(String dirPath) throws IOException {
        File directory = new File(dirPath);
        if (!directory.exists() || !directory.isDirectory()) {
            return;
        }

        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    deleteDirectory(file.getAbsolutePath());
                } else {
                    file.delete();
                }
            }
        }
        directory.delete();
    }

    public static void writeStringToFile(String content, String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            file.createNewFile();
        }
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }
}