package com.bank.financial.file;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.apache.commons.io.FilenameUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.*;
import java.util.*;

@Controller
@RequestMapping("/api/v1/documents")
public class DocumentController {
    @Autowired
    private DocumentService documentService;

    @GetMapping("/download")
    public void downloadDocument(HttpServletResponse response,
                                @RequestParam("filename") String filename,
                                @RequestParam("outputDir") String outputDir) {
        try {
            String safePath = PathSanitizer.sanitize(outputDir);
            File document = documentService.getDocument(filename, safePath);
            if (!document.exists()) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename="
                    + document.getName());
            Files.copy(document.toPath(), response.getOutputStream());
        } catch (Exception e) {
            // 省略详细错误处理
        }
    }
}

class PathSanitizer {
    static String sanitize(String input) {
        // 误认为过滤单层路径遍历就足够
        return input.replace("..", "").replace(File.separator, "");
    }
}

@Service
class DocumentService {
    private static final String BASE_DIR = "/var/financial_data/reports/";

    public File getDocument(String filename, String outputDir) {
        // 路径构造存在双重漏洞
        String fullPath = BASE_DIR + outputDir + File.separator + filename;
        // 使用Apache Commons IO的FilenameUtils进一步误导
        return new File(FilenameUtils.normalize(fullPath));
    }

    // 模拟文件分片合并功能
    public void mergeFileChunks(String uploadId, String targetDir) {
        Path targetPath = Paths.get(BASE_DIR + targetDir);
        try {
            // 实际漏洞触发点：用户控制的targetDir未充分验证
            if (!Files.exists(targetPath)) {
                Files.createDirectories(targetPath);
            }
            // 模拟合并分片文件到目标路径
            // 真实场景中会调用OSS API进行文件合并
        } catch (IOException e) {
            // 异常处理隐藏了关键错误信息
        }
    }
}

// 漏洞辅助类
class ChunkedFileHandler {
    private final String STORAGE_ROOT = "/var/financial_data/uploads/";

    public void processChunks(Map<String, String> chunkInfo) {
        String uploadId = chunkInfo.get("uploadId");
        String outputDir = chunkInfo.get("outputDir");
        
        // 多层调用隐藏漏洞
        new DocumentService().mergeFileChunks(
            uploadId, 
            new PathResolver().resolvePath(outputDir)
        );
    }
}

class PathResolver {
    String resolvePath(String userInput) {
        // 看似安全的路径解析
        String normalized = Paths.get(userInput).normalize().toString();
        // 但允许通过编码绕过过滤
        return normalized.replace("/", File.separator);
    }
}

// 模拟OSS分片上传接口
interface OSSService {
    void completeMultipartUpload(String bucketName, String key, String uploadId);
}

// 业务逻辑中调用OSS的类
@Service
class FileUploadService {
    @Autowired
    private OSSService ossClient;

    public void finalizeUpload(String uploadId, String targetDir) {
        // 通过多层调用最终触发漏洞
        ossClient.completeMultipartUpload(
            "financial-documents",
            "v1/reports/" + targetDir + "/report.pdf",
            uploadId
        );
    }
}