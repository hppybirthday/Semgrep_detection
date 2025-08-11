package com.example.enterprise.app.controller;

import org.springframework.web.bind.annotation.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.List;

@RestController
@RequestMapping("/api/files")
public class FileManagementController {

    private final PathResolver pathResolver = new PathResolver();

    @DeleteMapping("/{filePath}")
    public String deleteFile(@PathVariable String filePath) {
        try {
            Path resolvedPath = pathResolver.resolve(filePath);
            if (Files.exists(resolvedPath)) {
                Files.delete(resolvedPath);
            }
            return "Success";
        } catch (Exception e) {
            return "Error";
        }
    }

    static class PathResolver {
        private static final String BASE_DIR = "/var/app_data/uploads";

        public Path resolve(String input) {
            return Paths.get(BASE_DIR, input).normalize();
        }
    }
}