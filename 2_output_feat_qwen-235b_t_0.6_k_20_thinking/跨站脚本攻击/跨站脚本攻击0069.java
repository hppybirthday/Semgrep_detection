package com.crm.admanager.controller;

import com.crm.admanager.service.AdService;
import com.crm.admanager.model.AdContent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 广告内容管理控制器
 * 处理广告创建和展示请求
 */
@Controller
@RequestMapping("/ads")
public class AdController {
    @Autowired
    private AdService adService;

    /**
     * 创建新广告
     * @param content 广告内容
     * @param title 广告标题
     * @return 重定向到广告展示页
     */
    @PostMapping("/create")
    public String createAd(@RequestParam String content, @RequestParam String title) {
        AdContent ad = new AdContent();
        ad.setTitle(title);
        ad.setRawContent(content);
        adService.saveAd(ad);
        return "redirect:/ads/view?title=" + title;
    }

    /**
     * 展示指定标题的广告
     * @param title 广告标题
     * @param model 用于传递数据到视图
     * @return 视图名称
     */
    @GetMapping("/view")
    public String viewAd(@RequestParam String title, Map<String, Object> model) {
        AdContent ad = adService.getAdByTitle(title);
        model.put("adContent", ad.getDisplayContent());
        return "ad_template";
    }
}

// 服务层实现
package com.crm.admanager.service;

import com.crm.admanager.model.AdContent;
import com.crm.admanager.repository.AdRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AdService {
    @Autowired
    private AdRepository adRepository;

    /**
     * 保存广告内容
     * @param ad 广告对象
     */
    public void saveAd(AdContent ad) {
        ad.setProcessedContent(formatContent(ad.getRawContent()));
        adRepository.save(ad);
    }

    /**
     * 获取广告内容
     * @param title 广告标题
     * @return 广告对象
     */
    public AdContent getAdByTitle(String title) {
        return adRepository.findByTitle(title);
    }

    /**
     * 格式化内容
     * @param content 原始内容
     * @return 处理后的内容
     */
    private String formatContent(String content) {
        StringBuilder buffer = new StringBuilder();
        buffer.append("<div class='ad-body'>");
        buffer.append(content);
        buffer.append("</div>");
        return buffer.toString();
    }
}

// 模型类
package com.crm.admanager.model;

public class AdContent {
    private String title;
    private String rawContent;
    private String processedContent;

    // Getters and setters
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getRawContent() { return rawContent; }
    public void setRawContent(String rawContent) { this.rawContent = rawContent; }
    public String getProcessedContent() { return processedContent; }
    public void setProcessedContent(String processedContent) { this.processedContent = processedContent; }
    public String getDisplayContent() { return processedContent; }
}

// 存储库接口
package com.crm.admanager.repository;

import com.crm.admanager.model.AdContent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AdRepository extends JpaRepository<AdContent, Long> {
    AdContent findByTitle(String title);
}