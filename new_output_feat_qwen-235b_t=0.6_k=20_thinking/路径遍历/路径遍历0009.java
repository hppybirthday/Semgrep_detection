package com.bigdata.secure.storage;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/data")
public class FileUploadController {
    @Autowired
    private FileStorageService fileStorage;

    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file,
                          @RequestParam("path") String inputPath) {
        try {
            String result = fileStorage.saveFile(file, inputPath);
            return "File saved at: " + result;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

@Service
class FileStorageService {
    private static final String BASE_PATH = Global.getDownloadPath();
    private final PathValidator pathValidator = new PathValidator();

    public String saveFile(MultipartFile file, String inputPath) throws IOException {
        Path targetPath = Paths.get(BASE_PATH, inputPath);
        
        // Simulated validation chain
        if (!pathValidator.validate(targetPath.toString())) {
            throw new SecurityException("Invalid path");
        }

        // Vulnerable file operation
        File targetFile = targetPath.toAbsolutePath().normalize().toFile();
        
        // Simulated data processing
        if (!targetFile.getParentFile().exists()) {
            targetFile.getParentFile().mkdirs();
        }
        
        file.transferTo(targetFile);
        return targetFile.getAbsolutePath();
    }
}

class PathValidator {
    // Simulated security check with misleading logic
    boolean validate(String path) {
        try {
            File baseDir = new File(BASE_PATH);
            File targetFile = new File(path);
            
            // Vulnerable check that can be bypassed
            if (!targetFile.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
                return false;
            }
            
            // Additional checks with false sense of security
            List<String> restrictedDirs = Arrays.asList("/etc", "/boot", "/proc");
            for (String dir : restrictedDirs) {
                if (path.contains(dir)) return false;
            }
            
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}

// Simulated global configuration
class Global {
    // Vulnerable configuration point
    private static final String DOWNLOAD_PATH = System.getenv("DATA_DIR");
    
    static String getDownloadPath() {
        return DOWNLOAD_PATH != null ? DOWNLOAD_PATH : "/var/data";
    }
}