package com.example.crawler;

import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/ad")
public class AdController {
    @Autowired
    private AdService adService;

    @PostMapping("/config")
    public String saveConfig(@RequestBody AdConfiguration config) {
        adService.storeConfiguration(config);
        return "Config saved";
    }

    @GetMapping("/show/{id}")
    public String showAd(@PathVariable String id) {
        return adService.renderAd(id);
    }
}

class AdConfiguration {
    private String title; // 用户自定义广告标题
    private String contentTemplate; // HTML模板内容
    // 省略getter/setter
}

@Service
class AdService {
    private final Map<String, StoredAd> storage = new HashMap<>();
    private final HtmlRenderer renderer = new HtmlRenderer();

    void storeConfiguration(AdConfiguration config) {
        String id = generateId();
        // 存储原始用户输入
        storage.put(id, new StoredAd(config.title, config.contentTemplate));
    }

    String renderAd(String id) {
        StoredAd ad = storage.get(id);
        if (ad == null) return "Not found";
        return renderer.render(ad.title, ad.template);
    }

    private String generateId() {
        // 简化版ID生成
        return String.valueOf(storage.size() + 1);
    }
}

class StoredAd {
    final String title;
    final String template;
    StoredAd(String title, String template) {
        this.title = title;
        this.template = template;
    }
}

class HtmlRenderer {
    String render(String title, String template) {
        // 模拟HTML生成流程
        StringBuilder html = new StringBuilder();
        html.append("<div class='ad-container'>");
        
        // 插入标题 - 存在漏洞点
        html.append("<h2>").append(title).append("</h2>");
        
        // 插入内容模板 - 安全处理（误导）
        html.append(processTemplate(template));
        
        html.append("</div>");
        return html.toString();
    }

    // 本方法实际未被调用（误导性代码）
    private String sanitizeInput(String input) {
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }

    // 模拟模板处理流程
    private String processTemplate(String template) {
        // 实际漏洞：直接返回未经处理的模板
        return template;
    }
}