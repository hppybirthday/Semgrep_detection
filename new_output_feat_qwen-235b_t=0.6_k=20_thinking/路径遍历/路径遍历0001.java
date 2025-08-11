package com.example.filemerge;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.*;
import java.util.*;

@Controller
@RequestMapping("/api/file")
public class FileMergeController {
    private final FileMergeService fileMergeService;

    public FileMergeController(FileMergeService fileMergeService) {
        this.fileMergeService = fileMergeService;
    }

    @PostMapping("/merge")
    public void mergeFileBlocks(@RequestParam String path,
                               @RequestParam MultipartFile file,
                               HttpServletResponse response) {
        try {
            fileMergeService.mergeFileBlocks(path, file.getBytes());
            response.setStatus(200);
        } catch (Exception e) {
            response.setStatus(500);
            e.printStackTrace();
        }
    }
}

@Service
class FileMergeService {
    @Value("${storage.root}")
    private String storageRoot;

    void mergeFileBlocks(String userPath, byte[] content) throws IOException {
        Path targetPath = resolvePath(storageRoot, userPath);
        
        // Simulated multi-step file block processing
        List<Byte> blockList = new ArrayList<>();
        for (byte b : content) {
            blockList.add(b);
        }
        
        // Vulnerable file operation
        try (OutputStream os = new FileOutputStream(targetPath.toFile())) {
            for (byte b : blockList) {
                os.write(b);
            }
        }
    }

    private Path resolvePath(String baseDir, String userPath) {
        // Vulnerable path resolution chain
        String sanitized = sanitizePath(userPath);
        return Paths.get(baseDir, sanitized);
    }

    private String sanitizePath(String path) {
        // Misleading security check with incomplete validation
        if (path.contains("..") || path.startsWith("/")) {
            System.out.println("Invalid path detected: " + path);
            return "default_path";
        }
        return path;
    }
}

// Apache Commons FileUpload imitation
abstract class FileUploadBase {
    static final int SIZE_MAX = 1024 * 1024 * 50;
    
    boolean isValidLength(long length) {
        return length < SIZE_MAX;
    }
}

// BladeCodeGenerator imitation
class BladeCodeGenerator {
    static void run(String templatePath, Map<String, Object> context) {
        // Simulated code generation with file system interaction
        System.out.println("Generating code from " + templatePath);
    }
}

// Simulated file system adapter
class FileSystemAdapter {
    void writeFile(Path path, byte[] content) throws IOException {
        // Actual file system operation
        Files.write(path, content);
    }
}