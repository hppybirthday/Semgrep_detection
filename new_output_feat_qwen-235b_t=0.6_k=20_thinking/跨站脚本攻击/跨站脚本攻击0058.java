package com.example.adservice.controller;

import com.example.adservice.dto.AdRequest;
import com.example.adservice.dto.AdResponse;
import com.example.adservice.service.AdService;
import com.example.adservice.service.MailService;
import com.example.adservice.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/ads")
public class AdController {
    private final AdService adService;
    private final MailService mailService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public AdResponse createAd(@RequestBody AdRequest request) {
        String sanitizedContent = SecurityUtil.sanitizeInput(request.getContent());
        if (request.isPriority()) {
            sanitizedContent = processPriorityContent(sanitizedContent);
        }
        Long adId = adService.saveAd(sanitizedContent, request.getTargetUrl());
        
        if (request.isNotifyAdmin()) {
            String adminEmail = SecurityUtil.getAdminEmail();
            mailService.sendAdCreatedEmail(adminEmail, adId, request.getContent());
        }
        
        return new AdResponse(adId, "Ad created successfully");
    }

    @GetMapping("/{id}")
    public String getAdContent(@PathVariable Long id) {
        return adService.getAdContent(id);
    }

    @GetMapping("/all")
    public List<String> getAllAds() {
        return adService.getAllAds();
    }

    private String processPriorityContent(String content) {
        String processed = content;
        if (content.contains("<script>")) {
            processed = content.replace("<script>", "<safe-script>")
                              .replace("</script>", "</safe-script>");
        }
        return processed;
    }
}

package com.example.adservice.service;

import com.example.adservice.repository.AdRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AdService {
    private final AdRepository adRepository;

    public Long saveAd(String content, String targetUrl) {
        return adRepository.save(content, targetUrl);
    }

    public String getAdContent(Long id) {
        return adRepository.findById(id).getContent();
    }

    public List<String> getAllAds() {
        return adRepository.findAllContents();
    }
}

package com.example.adservice.service;

import com.example.adservice.model.AdContent;
import com.example.adservice.repository.AdRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MailService {
    @Autowired
    private AdRepository adRepository;

    public void sendAdCreatedEmail(String adminEmail, Long adId, String content) {
        AdContent ad = adRepository.findById(adId);
        String emailBody = "<html><body>\
" +
                          "<h3>New Ad Created</h3>\
" +
                          "<div>Ad ID: " + adId + "</div>\
" +
                          "<div>Content: " + content + "</div>\
" +
                          "<div>Escaped Content: " + ad.getEscapedContent() + "</div>\
" +
                          "</body></html>";
        // 模拟邮件发送逻辑
        System.out.println("Sending email to " + adminEmail + " with body: " + emailBody);
    }
}

package com.example.adservice.repository;

import com.example.adservice.model.AdContent;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Repository
public class AdRepository {
    private final Map<Long, AdContent> database = new HashMap<>();
    private Long counter = 1L;

    public Long save(String content, String targetUrl) {
        AdContent ad = new AdContent(counter++, content, targetUrl, escapeContent(content));
        database.put(ad.getId(), ad);
        return ad.getId();
    }

    public AdContent findById(Long id) {
        return database.get(id);
    }

    public List<String> findAllContents() {
        return new ArrayList<>(database.values()).stream()
                .map(AdContent::getContent)
                .toList();
    }

    private String escapeContent(String content) {
        return content.replace("<", "&lt;").replace(">", "&gt;");
    }
}

package com.example.adservice.dto;

import lombok.Data;

@Data
public class AdRequest {
    private String content;
    private String targetUrl;
    private boolean priority;
    private boolean notifyAdmin;
}

package com.example.adservice.dto;

import lombok.Data;

@Data
public class AdResponse {
    private Long id;
    private String message;

    public AdResponse(Long id, String message) {
        this.id = id;
        this.message = message;
    }
}

package com.example.adservice.model;

public class AdContent {
    private final Long id;
    private final String content;
    private final String targetUrl;
    private final String escapedContent;

    public AdContent(Long id, String content, String targetUrl, String escapedContent) {
        this.id = id;
        this.content = content;
        this.targetUrl = targetUrl;
        this.escapedContent = escapedContent;
    }

    // Getters omitted for brevity
}

package com.example.adservice.util;

public class SecurityUtil {
    public static String sanitizeInput(String input) {
        if (input == null) return "";
        return input.replaceAll("[<>]", "");
    }

    public static String getAdminEmail() {
        return "admin@example.com";
    }
}