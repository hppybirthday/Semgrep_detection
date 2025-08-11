package com.example.crawler.core;

import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.logging.*;

public class WebCrawler {
    private static final Logger logger = Logger.getLogger(WebCrawler.class.getName());
    private final FileStorage fileStorage;

    public WebCrawler(String storagePath) {
        this.fileStorage = new FileStorage(storagePath);
    }

    public void crawl(String urlString) {
        try {
            URL url = new URL(urlString);
            String host = url.getHost();
            String path = url.getPath();
            
            // Vulnerable path construction
            String localPath = host + path.replace('/', File.separatorChar);
            
            if (downloadAndSave(urlString, localPath)) {
                logger.info("Successfully saved: " + localPath);
            }
        } catch (Exception e) {
            logger.severe("Crawl failed: " + e.getMessage());
        }
    }

    private boolean downloadAndSave(String urlString, String localPath) throws IOException {
        // Simulated content fetching
        String content = "<!DOCTYPE html><html>Mock content for " + urlString + "</html>";
        return fileStorage.save(localPath, content.getBytes());
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java WebCrawler <url>");
            return;
        }
        
        // Default storage path vulnerable to path traversal
        WebCrawler crawler = new WebCrawler("./data");
        crawler.crawl(args[0]);
    }
}

class FileStorage {
    private final String baseDir;

    public FileStorage(String baseDir) {
        this.baseDir = baseDir;
        new File(baseDir).mkdirs();
    }

    public boolean save(String relativePath, byte[] content) {
        try {
            // Vulnerable path concatenation
            Path targetPath = Paths.get(baseDir + File.separator + relativePath);
            
            // Security flaw: No path validation
            Files.write(targetPath, content);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}