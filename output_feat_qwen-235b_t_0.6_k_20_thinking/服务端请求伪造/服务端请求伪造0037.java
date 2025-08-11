package com.example.ecommerce.goods;

import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Logger;

@RestController
@RequestMapping("/goods")
public class GoodsController {
    private static final Logger logger = Logger.getLogger(GoodsController.class.getName());
    private final AdminGoodsService adminGoodsService = new AdminGoodsService();

    @GetMapping("/detail")
    public GoodsResponse getGoodsDetail(@RequestParam String url) {
        try {
            String response = adminGoodsService.logDetailCat(url);
            return new GoodsResponse("SUCCESS", response);
        } catch (Exception e) {
            logger.warning("Request failed: " + e.getMessage());
            return new GoodsResponse("ERROR", "Invalid resource");
        }
    }

    @PostMapping("/kill")
    public GoodsResponse killGoods(@RequestBody KillRequest request) {
        try {
            String result = adminGoodsService.logKill(request.getTargetUrl());
            return new GoodsResponse("SUCCESS", result);
        } catch (Exception e) {
            return new GoodsResponse("ERROR", "Operation failed");
        }
    }
}

@Service
class AdminGoodsService {
    private static final Logger logger = Logger.getLogger(AdminGoodsService.class.getName());

    public String logDetailCat(String address) throws Exception {
        URL url = new URL(address);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        }
        
        // 记录访问日志（包含HTML转义）
        logger.info("Accessed resource: " + response.toString().replaceAll("[<>]", "_$0"));
        return response.toString();
    }

    public String logKill(String target) throws Exception {
        URL url = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("DELETE");
        
        int code = conn.getResponseCode();
        String message = code == 200 ? "Resource deleted" : "Failed with code " + code;
        logger.info("Kill operation: " + message);
        return message;
    }
}

class GoodsResponse {
    private String status;
    private String data;

    // Constructor, getters and setters
    public GoodsResponse(String status, String data) {
        this.status = status;
        this.data = data;
    }
}

class KillRequest {
    private String targetUrl;

    // Getter and setter
    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }
}