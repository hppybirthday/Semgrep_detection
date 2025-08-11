package com.example.docsrv.controller;

import com.example.docsrv.service.DocumentService;
import com.example.docsrv.util.PathResolver;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/documents")
public class DocumentController {
    private final DocumentService documentService = new DocumentService();
    private final PathResolver pathResolver = new PathResolver();

    /**
     * 处理文档预览请求
     * @param docId 文档标识
     * @return 预览结果
     */
    @GetMapping("/preview")
    public String handlePreview(@RequestParam String docId) {
        try {
            String basePath = pathResolver.resolveBasePath();
            String safePath = pathResolver.normalizePath(basePath, docId);
            
            if (!pathResolver.checkPathTraversal(safePath)) {
                return "Invalid document path";
            }

            if (!documentService.validateDocumentFormat(safePath)) {
                return "Unsupported document format";
            }

            String cmd = "cat " + safePath;
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            
            return documentService.readStream(process.getInputStream());
            
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Internal server error";
        }
    }
}

// --- Service Classes ---

class PathResolver {
    String resolveBasePath() {
        return System.getenv("DOC_ROOT");
    }

    String normalizePath(String basePath, String docId) {
        return basePath + "/" + docId.replace("..", "");
    }

    boolean checkPathTraversal(String path) {
        return path.startsWith(System.getenv("DOC_ROOT"));
    }
}

class DocumentService {
    boolean validateDocumentFormat(String path) {
        return path.endsWith(".txt") || path.endsWith(".md");
    }

    String readStream(java.io.InputStream stream) throws IOException {
        java.util.Scanner s = new java.util.Scanner(stream).useDelimiter("\\\\A");
        return s.hasNext() ? s.next() : "";
    }
}