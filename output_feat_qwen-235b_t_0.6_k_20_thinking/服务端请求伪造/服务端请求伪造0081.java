package com.example.crawler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SpringBootApplication
@RestController
@RequestMapping("/joblog")
public class VulnerableCrawler {

    @GetMapping("/logDetailCat")
    public String crawlLog(@RequestParam String address) {
        return processRequest(address);
    }

    @PostMapping("/logKill")
    public String killLog(@RequestParam String address) {
        return processRequest(address);
    }

    private String processRequest(String targetUrl) {
        try {
            URL url = new URL(targetUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            int responseCode = connection.getResponseCode();
            StringBuilder response = new StringBuilder();

            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(connection.getInputStream()));
                String line;
                while ((line = in.readLine()) != null) {
                    response.append(line);
                }
                in.close();
            }

            // 模拟解析JSON并返回部分数据
            return extractJsonField(response.toString(), "importantData");

        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }

    private String extractJsonField(String json, String field) {
        Pattern pattern = Pattern.compile("\\"" + field + "\\"\\s*:\\s*\\"([^\\"]+)\\"");
        Matcher matcher = pattern.matcher(json);
        return matcher.find() ? matcher.group(1) : "Not found";
    }

    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawler.class, args);
    }
}