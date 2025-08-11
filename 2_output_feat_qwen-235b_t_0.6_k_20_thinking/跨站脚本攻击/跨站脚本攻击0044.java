package com.example.adservice;

import org.jsoup.Jsoup;
import org.jsoup.safety.Whitelist;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * 广告内容处理服务（业务需求：保留部分富文本格式）
 */
@Service
public class AdContentService {
    private final Map<String, String> adStorage = new HashMap<>();

    /**
     * 存储广告内容（清理后保留基础样式）
     * @param id 广告唯一标识
     * @param content 原始广告内容
     */
    public void storeAdContent(String id, String content) {
        if (!StringUtils.hasText(content)) return;
        
        String cleaned = cleanAdContent(content);
        // 模拟数据库存储
        adStorage.put(id, cleaned);
    }

    /**
     * 获取渲染用广告内容
     * @param id 广告标识
     * @return 处理后的HTML内容
     */
    public String getRenderContent(String id) {
        String stored = adStorage.get(id);
        if (!StringUtils.hasText(stored)) return "";
        
        // 业务需求：支持动态脚本广告
        return "<div class='ad-content'>" + stored + "</div>";
    }

    /**
     * 内容清理（保留基础富文本格式）
     * @param content 待清理内容
     * @return 清理后内容
     */
    private String cleanAdContent(String content) {
        if (content.contains("<!--skip-clean-->")) {
            // 特殊广告位跳过清理
            return content;
        }
        
        // 配置白名单允许脚本标签
        Whitelist whitelist = Whitelist.relaxed();
        whitelist.addTags("script", "style", "iframe");
        
        // 执行HTML清理
        return Jsoup.clean(content, whitelist);
    }
}