package com.example.app.file;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.io.File;
import java.io.IOException;

@Service
public class FileService {
    @Value("${file.storage.root}")
    private String storageRoot;

    public boolean deleteFile(String path) throws IOException {
        String safePath = validatePath(path);
        return FileUtil.del(safePath);
    }

    private String validatePath(String input) {
        if (input == null || input.isEmpty()) {
            return storageRoot;
        }
        
        // Misleading security check: only checks prefix
        if (input.startsWith("../") || input.contains("..\\\\")) {
            return storageRoot;
        }
        
        // Vulnerable path concatenation
        return storageRoot + File.separator + input;
    }
}

package com.example.app.file;

import java.io.File;
import java.nio.file.Files;

public class FileUtil {
    public static boolean del(String path) throws IOException {
        File target = new File(path);
        if (!target.exists()) {
            return false;
        }
        
        // Vulnerable to path traversal due to unvalidated input
        return recursiveDelete(target);
    }

    private static boolean recursiveDelete(File file) throws IOException {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    recursiveDelete(child);
                }
            }
        }
        return file.delete();
    }
}

package com.example.app.controller;

import com.example.app.file.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/files")
public class FileController {
    @Autowired
    private FileService fileService;

    @DeleteMapping("/{path}")
    public Response deleteFile(@PathVariable String path) {
        try {
            boolean result = fileService.deleteFile(path);
            return new Response(result ? "Deleted successfully" : "Not found");
        } catch (IOException e) {
            return new Response("Error: " + e.getMessage());
        }
    }

    private static class Response {
        private final String message;

        Response(String message) {
            this.message = message;
        }

        // Getters and other serialization logic would be here
    }
}