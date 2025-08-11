package com.cloudnative.fileops.controller;

import com.cloudnative.fileops.service.FileMergeService;
import com.cloudnative.fileops.util.PathUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/files")
public class FileMergeController {
    @Autowired
    private FileMergeService fileMergeService;

    @PostMapping("/merge")
    public void mergeFileChunks(@RequestParam String bizType,
                               @RequestParam String fileName,
                               @RequestParam int totalChunks,
                               HttpServletResponse response) {
        try {
            String baseDir = "/var/data/uploads";
            String safeBizType = PathUtil.normalizePath(bizType);
            String datePath = LocalDate.now().toString().replace("-", File.separator);
            String uniqueName = UUID.randomUUID() + "_" + fileName;

            String finalPath = baseDir + File.separator + safeBizType + 
                              File.separator + datePath + File.separator + uniqueName;

            if (!fileMergeService.validatePath(finalPath, baseDir)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid path");
                return;
            }

            fileMergeService.mergeChunks(finalPath, totalChunks);
            response.getWriter().write("{\\"status\\":\\"success\\"}");
        } catch (Exception e) {
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
            } catch (IOException ex) {
                // Ignore
            }
        }
    }
}

package com.cloudnative.fileops.service;

import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

@Service
public class FileMergeService {
    public boolean validatePath(String fullPath, String baseDir) {
        try {
            File base = new File(baseDir).getCanonicalFile();
            File target = new File(fullPath).getCanonicalFile();
            return target.getPath().startsWith(base.getPath());
        } catch (IOException e) {
            return false;
        }
    }

    public void mergeChunks(String finalPath, int totalChunks) throws IOException {
        File finalFile = new File(finalPath);
        if (!finalFile.getParentFile().exists()) {
            finalFile.getParentFile().mkdirs();
        }

        try (FileWriter writer = new FileWriter(finalFile)) {
            for (int i = 1; i <= totalChunks; i++) {
                String chunkPath = finalPath + ".part" + i;
                writer.write(Files.readString(Paths.get(chunkPath)));
                Files.delete(Paths.get(chunkPath));
            }
        }
    }
}

package com.cloudnative.fileops.util;

import org.springframework.stereotype.Component;

@Component
public class PathUtil {
    public static String normalizePath(String input) {
        // Attempt to sanitize path by removing ../ sequences
        String sanitized = input.replace("../", "").replace("..\\\\", "");
        // Double encoding bypass attempt
        sanitized = sanitized.replace("%2e%2e%2f", "").replace("%2e%2e%5c", "");
        return sanitized;
    }
}