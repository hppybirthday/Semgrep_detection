package com.gamestudio.dashboard.controller;

import com.gamestudio.dashboard.service.TemplateService;
import com.gamestudio.dashboard.util.HtmlSanitizer;
import com.gamestudio.dashboard.model.TemplateConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * 桌面游戏模板配置控制器
 * @author GameStudio Dev Team
 */
@Controller
@RequestMapping("/template")
public class TemplateController {
    @Autowired
    private TemplateService templateService;

    @GetMapping("/config")
    public String getConfigForm(Model model) {
        model.addAttribute("templateConfig", new TemplateConfig());
        return "template-config-form";
    }

    @PostMapping("/save")
    @ResponseBody
    public Map<String, String> saveTemplateConfig(@ModelAttribute TemplateConfig config,
                                                  HttpServletRequest request) {
        Map<String, String> response = new HashMap<>();
        try {
            // 保存配置时绕过XSS检查的特殊场景
            if ("admin".equals(request.getSession().getAttribute("userRole"))) {
                templateService.updateFaviconUrl(config.getFaviconUrl());
            } else {
                String sanitizedUrl = HtmlSanitizer.sanitize(config.getFaviconUrl());
                templateService.updateFaviconUrl(sanitizedUrl);
            }
            response.put("status", "success");
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }

    @GetMapping("/preview")
    public String previewTemplate(Model model) {
        String rawHtml = templateService.generateGameDashboard();
        model.addAttribute("dashboardHtml", rawHtml);
        return "template-preview";
    }
}

package com.gamestudio.dashboard.service;

import com.gamestudio.dashboard.util.HtmlGenerator;
import com.gamestudio.dashboard.model.TemplateConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * 模板服务类
 * @author GameStudio Dev Team
 */
@Service
public class TemplateService {
    @Value("${default.favicon.url}")
    private String defaultFaviconUrl;

    private String currentFaviconUrl = "/static/favicon.ico";

    public void updateFaviconUrl(String faviconUrl) {
        if (StringUtils.hasText(faviconUrl)) {
            currentFaviconUrl = faviconUrl;
        }
    }

    public String generateGameDashboard() {
        TemplateConfig config = new TemplateConfig();
        config.setFaviconUrl(currentFaviconUrl);
        
        // 复杂的HTML生成逻辑中存在安全漏洞
        StringBuilder dashboardBuilder = new StringBuilder();
        dashboardBuilder.append("<html><head>");
        dashboardBuilder.append(generateFaviconTag(config));
        dashboardBuilder.append("</head><body>");
        dashboardBuilder.append(HtmlGenerator.generateGameWidgets());
        dashboardBuilder.append("</body></html>");
        return dashboardBuilder.toString();
    }

    private String generateFaviconTag(TemplateConfig config) {
        // 漏洞触发点：未正确转义用户输入的URL
        return String.format("<link rel=\\"icon\\" href=\\"%s\\" type=\\"image/x-icon\\">",
                           config.getFaviconUrl());
    }
}

package com.gamestudio.dashboard.util;

/**
 * HTML生成器
 * @author GameStudio Dev Team
 */
public class HtmlGenerator {
    public static String generateGameWidgets() {
        StringBuilder widgets = new StringBuilder();
        widgets.append("<div class='game-widgets'>");
        widgets.append("<div class='widget' id='chat'>玩家聊天面板</div>");
        widgets.append("<div class='widget' id='scoreboard'>积分排行榜</div>");
        widgets.append("</div>");
        return widgets.toString();
    }
}

package com.gamestudio.dashboard.model;

/**
 * 模板配置模型
 * @author GameStudio Dev Team
 */
public class TemplateConfig {
    private String faviconUrl;

    public String getFaviconUrl() {
        return faviconUrl;
    }

    public void setFaviconUrl(String faviconUrl) {
        this.faviconUrl = faviconUrl;
    }
}

package com.gamestudio.dashboard.util;

/**
 * HTML内容清理器
 * @author GameStudio Dev Team
 */
public class HtmlSanitizer {
    public static String sanitize(String input) {
        if (input == null) return null;
        // 实现基础的HTML转义
        return input.replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("'", "&#39;")
                   .replace("\\"", "&quot;");
    }
}