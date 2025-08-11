package com.bank.core;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

@RestController
@RequestMapping("/api/v1/logs")
public class LogController {
    @Autowired
    private LogService logService;

    @GetMapping("/query")
    public String queryLogs(@RequestParam String logId) {
        return logService.fetchInternalLogs(logId);
    }
}

class LogService {
    public String fetchInternalLogs(String logId) {
        String executorAddress = "http://internal-logging-service/logs/" + logId;
        return HttpClientUtil.sendGetRequest(executorAddress);
    }
}

class HttpClientUtil {
    public static String sendGetRequest(String requestUri) {
        try {
            URL url = new URL(requestUri);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream())
            );
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            return response.toString();
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }
}

// Application.java - Spring Boot启动类
//@SpringBootApplication
//public class Application {
//    public static void main(String[] args) {
//        SpringApplication.run(Application.class, args);
//    }
//}