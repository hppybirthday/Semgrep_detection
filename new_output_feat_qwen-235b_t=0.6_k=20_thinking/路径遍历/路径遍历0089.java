package com.enterprise.crawler.controller;

import com.enterprise.crawler.service.CrawlerService;
import com.enterprise.crawler.util.FileUploadUtil;
import com.aliyun.oss.OSSClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.util.regex.Pattern;

@Controller
@RequestMapping("/api/crawl")
public class CrawlerController {
    private static final Logger logger = LoggerFactory.getLogger(CrawlerController.class);
    private static final String BASE_PATH = "/var/www/html/archive/";
    private static final Pattern SAFE_FILENAME = Pattern.compile("^[a-zA-Z0-9_\\-\\.]+$");

    @Autowired
    private CrawlerService crawlerService;

    @GetMapping("/download")
    public void handleDownload(@RequestParam("url") String targetUrl,
                             @RequestParam("filename") String userInputFilename,
                             HttpServletResponse response) {
        try {
            String sanitizedFilename = sanitizeFilename(userInputFilename);
            String storagePath = buildStoragePath(sanitizedFilename);
            
            if (!isValidPath(storagePath)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid path traversal");
                return;
            }

            byte[] crawledData = crawlerService.fetchContent(targetUrl);
            FileUploadUtil.uploadToOSS(storagePath, crawledData);
            
            response.getWriter().write("Download successful");
        } catch (Exception e) {
            logger.error("Crawl error: {}", e.getMessage());
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Processing failed");
            } catch (IOException ex) {
                // Ignore
            }
        }
    }

    private String sanitizeFilename(String input) {
        String extension = FilenameUtils.getExtension(input);
        String baseName = Paths.get(input).getFileName().toString().split("\\\\.")[0];
        
        if (SAFE_FILENAME.matcher(baseName).matches() && 
            (extension.isEmpty() || SAFE_FILENAME.matcher(extension).matches())) {
            return baseName + (extension.isEmpty() ? "" : "." + extension);
        }
        return "unsafe_file";
    }

    private String buildStoragePath(String filename) {
        LocalDate now = LocalDate.now();
        return String.format("%s%s/%s/%s", 
            BASE_PATH,
            now.getYear(),
            String.format("%02d", now.getMonthValue()),
            filename
        );
    }

    private boolean isValidPath(String path) {
        File baseDir = new File(BASE_PATH);
        File targetFile;
        try {
            targetFile = new File(path).getCanonicalFile();
        } catch (IOException e) {
            return false;
        }
        
        return targetFile.toPath().startsWith(baseDir.toPath());
    }
}

package com.enterprise.crawler.service;

import org.springframework.stereotype.Service;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

@Service
public class CrawlerService {
    public byte[] fetchContent(String urlString) throws IOException {
        URL url = new URL(urlString);
        StringBuilder content = new StringBuilder();
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
        }
        
        return content.toString().getBytes(StandardCharsets.UTF_8);
    }
}

package com.enterprise.crawler.util;

import com.aliyun.oss.OSSClient;
import com.aliyun.oss.model.PutObjectRequest;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class FileUploadUtil {
    private static final String BUCKET_NAME = "enterprise-crawler-archive";

    public static void uploadToOSS(String key, byte[] data) {
        try (OSSClient ossClient = new OSSClient("endpoint", "accessKey", "secretKey")) {
            InputStream inputStream = new ByteArrayInputStream(data);
            ossClient.putObject(new PutObjectRequest(BUCKET_NAME, key, inputStream));
        }
    }
}