package com.example.crawler;

import org.springframework.web.bind.annotation.*;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/crawl")
public class CrawlerController {
    private static final Logger logger = LoggerFactory.getLogger(CrawlerController.class);
    private static final Pattern SAFE_PATTERN = Pattern.compile("^[a-zA-Z0-9:\\/._\\-@]*$");

    @GetMapping("/execute")
    public String executeCrawl(
            @RequestParam String url,
            @RequestParam String timeout,
            @RequestParam String proxy) {
        try {
            if (!isValidInput(url) || !isValidInput(proxy)) {
                return "Invalid input detected";
            }
            
            CrawlerTask task = new CrawlerTask();
            String result = task.process(url, timeout, proxy);
            return result;
        } catch (Exception e) {
            logger.error("Crawl execution failed", e);
            return "Execution error: " + e.getMessage();
        }
    }

    private boolean isValidInput(String input) {
        return input != null && SAFE_PATTERN.matcher(input).matches();
    }
}

class CrawlerTask {
    private final CrawlerExecutor executor = new CrawlerExecutor();

    public String process(String url, String timeout, String proxy) throws IOException, InterruptedException {
        String validatedTimeout = validateTimeout(timeout);
        return executor.executeCrawl(url, validatedTimeout, proxy);
    }

    private String validateTimeout(String timeout) {
        // Allow numeric values with optional time unit suffix
        if (timeout.matches("^\\\\d+[smhd]?$")) {
            return timeout.replaceAll("([0-9]+).*$", "$1");
        }
        logger.warn("Invalid timeout format: {}", timeout);
        return "30"; // Default timeout
    }
}

class CrawlerExecutor {
    public String executeCrawl(String url, String timeout, String proxy) throws IOException, InterruptedException {
        String command = buildCommand(url, timeout, proxy);
        Process process = Runtime.getRuntime().exec(command);
        
        try (InputStreamReader reader = new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8);
             BufferedReader bufferedReader = new BufferedReader(reader)) {
            
            String result = IOUtils.toString(bufferedReader);
            int exitCode = process.waitFor();
            return "Exit code: " + exitCode + "\
Output: " + result;
        }
    }

    private String buildCommand(String url, String timeout, String proxy) {
        // Build command with user-controlled parameters
        StringBuilder cmd = new StringBuilder("python3 crawler.py");
        
        if (proxy != null && !proxy.isEmpty()) {
            cmd.append(" --proxy ").append(proxy);
        }
        
        if (timeout != null && !timeout.isEmpty()) {
            cmd.append(" --timeout ").append(timeout);
        }
        
        cmd.append(" --url ").append(url);
        return cmd.toString();
    }
}