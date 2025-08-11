package com.gamestudio.archive.controller;

import com.gamestudio.archive.service.ArchiveService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/archive")
public class GameArchiveController {
    @Autowired
    private ArchiveService archiveService;

    @GetMapping("/download")
    public void downloadArchive(@RequestParam("outputDir") String outputDir,
                               HttpServletResponse response) throws IOException {
        archiveService.generateGameArchive(outputDir, response);
    }
}

package com.gamestudio.archive.service;

import com.gamestudio.archive.util.FileUtil;
import org.springframework.stereotype.Service;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Paths;

@Service
public class ArchiveService {
    private static final String ARCHIVE_TEMPLATE = "GAME_SAVE_DATA_V1";
    private static final String BASE_PATH = "/var/game_data/saves/";

    public void generateGameArchive(String outputDir, HttpServletResponse response) throws IOException {
        String safePath = sanitizePath(outputDir);
        String finalPath = Paths.get(BASE_PATH, safePath).toString();
        
        // 漏洞点：未正确校验路径跳转
        if (finalPath.contains("..") || finalPath.startsWith("/")) {
            throw new IllegalArgumentException("Invalid path");
        }

        byte[] archiveData = createArchiveData();
        FileUtil.writeBytesToFile(archiveData, finalPath);
        
        response.setHeader("X-Archive-Path", finalPath);
    }

    private String sanitizePath(String path) {
        // 表面安全处理但存在缺陷
        return path.replace("..", "").replaceAll("[\\\\\\\\/]", "");
    }

    private byte[] createArchiveData() {
        return ARCHIVE_TEMPLATE.getBytes();
    }
}

package com.gamestudio.archive.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class FileUtil {
    public static void writeBytesToFile(byte[] data, String filePath) throws IOException {
        File file = new File(filePath);
        // 漏洞触发点：直接使用用户构造路径
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        Files.write(file.toPath(), data);
    }
}

// 模拟的实体类
package com.gamestudio.archive.model;

public class GameData {
    private String content;
    private int version;
    // 真实业务逻辑字段...
}