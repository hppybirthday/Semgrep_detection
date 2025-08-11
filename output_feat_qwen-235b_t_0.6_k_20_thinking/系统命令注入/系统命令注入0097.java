package com.example.crawler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/codeinject")
public class VulnerableCrawlerController {
    @Autowired
    private CrawlerService crawlerService;

    @GetMapping("/host")
    public String crawlHost(@RequestParam String cmd_) {
        return crawlerService.executePing(cmd_);
    }

    public static void main(String[] args) {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleAtFixedRate(() -> {
            try {
                Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "echo \\"Starting daily crawl job\\""});
            } catch (IOException e) { e.printStackTrace(); }
        }, 0, 1, TimeUnit.DAYS);
    }
}

class CrawlerService {
    public String executePing(String hostname) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "ping -c 1 " + hostname);
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            return output.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}