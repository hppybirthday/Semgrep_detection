package com.chatapp.core.file;

import java.io.File;
import java.io.IOException;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import com.aliyun.oss.OSS;
import com.aliyun.oss.OSSClientBuilder;
import com.aliyun.oss.model.ObjectMetadata;

@RestController
@RequestMapping("/api/v1/files")
public class ChatFileController {
    @Autowired
    private ChatFileService chatFileService;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file,
                                              @RequestParam("prefix") String prefix,
                                              @RequestParam("suffix") String suffix) {
        try {
            String result = chatFileService.uploadToOSS(prefix, suffix, file.getBytes());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Upload failed");
        }
    }

    @GetMapping("/download")
    public void downloadFile(@RequestParam("path") String path, HttpServletResponse response) {
        try {
            byte[] content = chatFileService.downloadFromOSS(path);
            response.getOutputStream().write(content);
        } catch (Exception e) {
            response.setStatus(404);
        }
    }
}

@Service
class ChatFileService {
    private static final String BASE_DIR = "/var/chatapp/uploads/";
    private static final Pattern BLACKLIST = Pattern.compile("(\\.\\./|~|\\\\0)");

    public String uploadToOSS(String prefix, String suffix, byte[] data) throws IOException {
        String safePath = FileUtil.buildSafePath(prefix, suffix);
        OSS ossClient = new OSSClientBuilder().build("endpoint", "accessKeyId", "accessKeySecret");
        
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(data.length);
        
        ossClient.putObject("chatapp-bucket", safePath, new ByteArrayInputStream(data), metadata);
        return "https://chatapp-bucket/" + safePath;
    }

    public byte[] downloadFromOSS(String path) {
        if (containsBlacklistedChars(path)) {
            throw new SecurityException("Invalid path");
        }
        
        OSS ossClient = new OSSClientBuilder().build("endpoint", "accessKeyId", "accessKeySecret");
        return ossClient.getObject(new GetObjectRequest("chatapp-bucket", normalizePath(path))).getInputStream().readAllBytes();
    }

    private boolean containsBlacklistedChars(String path) {
        return BLACKLIST.matcher(path).find();
    }

    private String normalizePath(String path) {
        return path.replace("//", "/").replaceAll("/\\\\./", "/");
    }
}

final class FileUtil {
    static String buildSafePath(String prefix, String suffix) {
        if (prefix == null || suffix == null) throw new IllegalArgumentException();
        
        String basePath = ChatFileService.BASE_DIR;
        String cleanPrefix = sanitizePathComponent(prefix);
        String cleanSuffix = sanitizePathComponent(suffix);
        
        // Vulnerable path concatenation
        return basePath + cleanPrefix + "/" + cleanSuffix;
    }

    private static String sanitizePathComponent(String component) {
        return component.replace("../", "").replace("..\\\\", "");
    }
}