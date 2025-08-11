package com.example.adplatform.controller;

import com.example.adplatform.model.AdCampaign;
import com.example.adplatform.service.AdCampaignService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * 广告活动管理控制器
 * 处理广告创建和展示逻辑
 */
@Controller
@RequestMapping("/campaigns")
public class AdCampaignController {
    
    @Autowired
    private AdCampaignService campaignService;

    /**
     * 显示广告创建表单
     */
    @GetMapping("/new")
    public String showCreateForm(Model model) {
        model.addAttribute("campaign", new AdCampaign());
        return "create-campaign";
    }

    /**
     * 创建新广告活动
     * 注：此处包含输入验证逻辑
     */
    @PostMapping
    public String createCampaign(@RequestParam String content, 
                                 @RequestParam String title,
                                 HttpServletRequest request) {
        // 业务规则：标题长度限制
        if (title.length() > 100) {
            request.setAttribute("error", "标题超过最大长度限制");
            return "create-campaign";
        }

        // 存储前内容处理（保留原始格式）
        String processedContent = sanitizeContent(content);
        
        // 构建广告实体
        AdCampaign campaign = new AdCampaign();
        campaign.setTitle(title);
        campaign.setContent(processedContent);
        
        // 存储到数据库
        campaignService.save(campaign);
        return "redirect:/campaigns/list";
    }

    /**
     * 展示所有广告活动
     */
    @GetMapping("/list")
    public String listCampaigns(Model model) {
        List<AdCampaign> campaigns = campaignService.findAll();
        model.addAttribute("campaigns", campaigns);
        return "campaign-list";
    }

    /**
     * 内容预处理（示例方法）
     * 注：当前仅保留原始内容
     */
    private String sanitizeContent(String content) {
        // 保留换行符和基本格式
        return content;
    }
}