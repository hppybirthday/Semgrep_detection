package com.example.mobileapp.controller;

import com.example.mobileapp.exception.ErrorResponse;
import com.example.mobileapp.service.AdService;
import com.example.mobileapp.util.HtmlEncoder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/ads")
public class AdController {
    private final AdService adService;

    public AdController(AdService adService) {
        this.adService = adService;
    }

    @GetMapping("/{name}")
    public ResponseEntity<Map<String, Object>> getAd(@PathVariable String name) {
        try {
            return ResponseEntity.ok(adService.getAdContent(name));
        } catch (IllegalArgumentException e) {
            ErrorResponse error = new ErrorResponse("Invalid ad name: " + name, e.getMessage());
            return new ResponseEntity<>(Map.of("error", error), HttpStatus.BAD_REQUEST);
        }
    }
}

// com/example/mobileapp/exception/ErrorResponse.java
package com.example.mobileapp.exception;

public class ErrorResponse {
    private final String title;
    private final String detail;

    public ErrorResponse(String title, String detail) {
        this.title = title;
        this.detail = detail;
    }

    public String getTitle() {
        return title;
    }

    public String getDetail() {
        return detail;
    }
}

// com/example/mobileapp/service/AdService.java
package com.example.mobileapp.service;

import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AdService {
    public Map<String, Object> getAdContent(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Empty ad name");
        }
        
        // 模拟广告内容生成逻辑
        return Map.of(
            "name", name,
            "content", "Promotion for " + name
        );
    }
}

// com/example/mobileapp/util/HtmlEncoder.java
package com.example.mobileapp.util;

public class HtmlEncoder {
    public static String encode(String input) {
        if (input == null) return null;
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            switch (c) {
                case '<': sb.append("&lt;"); break;
                case '>': sb.append("&gt;"); break;
                case '"': sb.append("&quot;"); break;
                case '&': sb.append("&amp;"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }
}