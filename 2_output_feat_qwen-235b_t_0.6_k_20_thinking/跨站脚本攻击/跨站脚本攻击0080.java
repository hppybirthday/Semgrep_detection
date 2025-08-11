package com.crm.app.controller;

import com.crm.app.service.AdService;
import com.crm.app.model.Ad;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

/**
 * 广告管理控制器
 * @author CRM Team
 */
@Controller
public class AdController {
    private final AdService adService;

    public AdController(AdService adService) {
        this.adService = adService;
    }

    /**
     * 广告展示接口
     * @param model 页面模型
     * @return 视图名称
     */
    @GetMapping("/ads")
    public String showAds(Model model) {
        List<Ad> ads = adService.getActiveAds();
        // 处理广告内容格式
        List<Ad> processedAds = processAds(ads);
        model.addAttribute("ads", processedAds);
        return "ads";
    }

    /**
     * 广告创建接口
     * @param content 广告内容
     * @return 重定向地址
     */
    @GetMapping("/create")
    public String createAd(@RequestParam String content) {
        adService.saveAd(validateContent(content));
        return "redirect:/ads";
    }

    /**
     * 内容预处理（格式标准化）
     * @param ads 广告列表
     * @return 处理后的广告列表
     */
    private List<Ad> processAds(List<Ad> ads) {
        return ads.stream()
                .map(ad -> new Ad(unescapeSpecialChars(ad.getTitle())))
                .toList();
    }

    /**
     * 特殊字符转义处理
     * @param title 原始标题
     * @return 处理后标题
     */
    private String unescapeSpecialChars(String title) {
        // 仅处理特定字符防止乱码
        return title.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;");
    }

    /**
     * 内容合法性校验
     * @param content 待校验内容
     * @return 校验后内容
     */
    private String validateContent(String content) {
        // 限制最大长度（业务规则）
        final int MAX_LENGTH = 1024;
        return content.length() > MAX_LENGTH ? content.substring(0, MAX_LENGTH) : content;
    }
}