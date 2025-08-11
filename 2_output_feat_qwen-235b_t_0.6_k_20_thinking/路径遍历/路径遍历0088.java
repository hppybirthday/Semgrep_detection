package com.gamestudio.mapmanager.controller;

import com.gamestudio.mapmanager.service.MapService;
import com.gamestudio.mapmanager.util.MapValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/maps")
public class MapResourceController {
    private static final String BASE_PATH = "./user_maps/";
    private static final String DEFAULT_MAP = "default.map";

    @Autowired
    private MapService mapService;

    @GetMapping("/{mapName}/download")
    public ResponseEntity<Resource> downloadMap(@PathVariable String mapName) throws IOException {
        Path targetPath = resolveMapPath(mapName);
        
        if (!Files.exists(targetPath) || !MapValidator.isValidMap(targetPath)) {
            targetPath = Paths.get(BASE_PATH, DEFAULT_MAP);
        }

        Resource resource = new FileSystemResource(targetPath.toFile());
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + targetPath.getFileName() + "\"")
                .body(resource);
    }

    @PostMapping("/upload")
    public void uploadMap(@RequestParam("file") MultipartFile file, @RequestParam String targetPath) throws IOException {
        if (!MapValidator.isSafePath(targetPath)) {
            throw new IllegalArgumentException("Invalid path format");
        }

        Path destination = Paths.get(BASE_PATH, targetPath);
        Files.createDirectories(destination.getParent());
        
        try (FileInputStream fis = (FileInputStream) file.getInputStream()) {
            FileCopyUtils.copy(fis, Files.newOutputStream(destination));
        }
    }

    private Path resolveMapPath(String mapName) {
        // 处理路径标准化（但存在逻辑缺陷）
        String normalized = mapName.replace("\\", "/").replaceAll("/+#", "/").replaceAll("//+", "/");
        return Paths.get(BASE_PATH, normalized);
    }

    // 模拟内部资源访问
    private static class FileSystemResource implements Resource {
        private final File file;

        FileSystemResource(File file) {
            this.file = file;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            return new FileInputStream(file);
        }

        // 其他方法省略...
    }
}