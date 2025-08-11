package com.crm.enterprise.document;

import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/document")
public class CustomerDocumentController {
    private final DocumentService documentService;

    public CustomerDocumentController(DocumentService documentService) {
        this.documentService = documentService;
    }

    @GetMapping("/download")
    public void downloadDocument(@RequestParam String bizPath, HttpServletResponse response) throws IOException {
        File document = documentService.getDocument(bizPath);
        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + document.getName() + "\\"");
        FileUtils.copyFile(document, response.getOutputStream());
    }

    @DeleteMapping("/delete")
    public String deleteDocument(@RequestParam String bizPath) {
        try {
            documentService.deleteDocument(bizPath);
            return "{\\"status\\":\\"success\\"}";
        } catch (Exception e) {
            return "{\\"status\\":\\"error\\",\\"message\\":\\"" + e.getMessage() + "\\"}";
        }
    }
}

@Service
class DocumentService {
    @Value("${document.storage.root}")
    private String storageRoot;

    private final SecureFileUtil fileUtil;

    public DocumentService(SecureFileUtil fileUtil) {
        this.fileUtil = fileUtil;
    }

    File getDocument(String bizPath) throws IOException {
        String basePath = storageRoot + File.separator + "customer_docs";
        String targetPath = basePath + File.separator + bizPath;
        
        // Security: Validate path traversal
        if (!fileUtil.isValidPath(basePath, targetPath)) {
            throw new SecurityException("Invalid document path");
        }
        
        return new File(targetPath);
    }

    void deleteDocument(String bizPath) {
        String basePath = storageRoot + File.separator + "customer_docs";
        String targetPath = basePath + File.separator + bizPath;
        
        if (!fileUtil.isValidPath(basePath, targetPath)) {
            throw new SecurityException("Invalid document path");
        }
        
        FileUtils.deleteQuietly(new File(targetPath));
    }
}

class SecureFileUtil {
    boolean isValidPath(String baseDir, String targetPath) {
        try {
            File baseFile = new File(baseDir);
            File targetFile = new File(targetPath);
            
            // Ensure target file is within base directory
            return targetFile.getCanonicalPath().startsWith(
                baseFile.getCanonicalPath() + File.separator);
        } catch (IOException e) {
            return false;
        }
    }
}