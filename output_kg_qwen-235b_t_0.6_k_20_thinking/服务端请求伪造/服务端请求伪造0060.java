package com.crm.example.controller;

import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;

@RestController
@RequestMapping("/api/contacts")
public class ContactController {
    // 模拟CRM系统中的联系人导入功能
    @GetMapping("/import")
    public String importContacts(@RequestParam String url) {
        // 漏洞点：直接使用用户提供的URL发起外部请求
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet(url);
        try {
            // 强制服务器发起任意HTTP请求（SSRF）
            String response = httpClient.execute(httpClient.execute(request));
            return "Imported contacts: " + EntityUtils.toString(response.getEntity());
        } catch (IOException e) {
            return "Import failed: " + e.getMessage();
        } finally {
            try { httpClient.close(); } catch (IOException ignored) {}
        }
    }

    // 模拟CRM数据同步功能
    @PostMapping("/sync")
    public String syncData(@RequestParam String targetUrl) {
        // 漏洞点：未验证目标地址的安全性
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet(targetUrl);
        try {
            // 攻击者可通过此接口访问内部API（如元数据服务）
            return "Sync response: " + EntityUtils.toString(httpClient.execute(request).getEntity());
        } catch (IOException e) {
            return "Sync failed: " + e.getMessage();
        }
    }

    // 模拟CRM通知中心功能
    @GetMapping("/notify")
    public String sendNotification(@RequestParam String webhook) {
        // 漏洞点：允许攻击者指定任意webhook地址
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet(webhook);
        try {
            // 攻击者可利用此功能发起内部网络扫描
            return "Webhook response: " + EntityUtils.toString(httpClient.execute(request).getEntity());
        } catch (IOException e) {
            return "Notification failed: " + e.getMessage();
        }
    }
}