package com.bank.financial.controller;

import com.bank.financial.service.FileService;
import com.bank.financial.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@Controller
public class DocumentDownloadController {
    @Autowired
    private FileService fileService;

    @GetMapping("/download/document")
    public @ResponseBody void downloadDocument(
            @RequestParam("fileName") String fileName,
            HttpServletResponse response) throws IOException {
        
        if (!FileUtil.isValidFileName(fileName)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file name");
            return;
        }

        File document = fileService.getDocument(fileName);
        
        if (document == null || !document.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + document.getName() + "\\"");
        
        FileUtil.transferFile(document, response.getOutputStream());
    }
}

package com.bank.financial.service;

import com.bank.financial.util.FileUtil;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class FileService {
    private static final String BASE_DIR = "/var/financial_documents";

    public File getDocument(String userInput) {
        try {
            String normalized = FileUtil.normalizePath(userInput);
            File target = new File(BASE_DIR + File.separator + normalized);
            
            if (!FileUtil.isSubPathOf(target, new File(BASE_DIR))) {
                return null;
            }
            
            return target;
            
        } catch (Exception e) {
            return null;
        }
    }
}

package com.bank.financial.util;

import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Paths;

@Component
public class FileUtil {
    public static boolean isValidFileName(String fileName) {
        return fileName != null && fileName.matches("^[a-zA-Z0-9_\\-\\.]+$");
    }

    public static String normalizePath(String path) {
        return Paths.get(path).normalize().toString();
    }

    public static boolean isSubPathOf(File child, File parent) {
        try {
            return child.getCanonicalPath().startsWith(parent.getCanonicalPath());
        } catch (Exception e) {
            return false;
        }
    }

    public static void transferFile(File source, OutputStream output) throws IOException {
        FileUtils.writeLines(output, FileUtils.readLines(source, "UTF-8"));
    }
}