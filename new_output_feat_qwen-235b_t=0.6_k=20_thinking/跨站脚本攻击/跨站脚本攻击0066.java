package com.gamestudio.dashboard.controller;

import com.gamestudio.dashboard.service.PlayerProfileService;
import com.gamestudio.dashboard.util.InputSanitizer;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import java.util.logging.Logger;

/**
 * 游戏仪表盘控制器，处理玩家配置文件和界面渲染
 * @author GameStudio Dev Team
 */
@Controller
@RequiredArgsConstructor
public class DashboardController {
    private static final Logger LOGGER = Logger.getLogger(DashboardController.class.getName());
    private final PlayerProfileService profileService;

    /**
     * 显示玩家配置文件页面
     * @param playerId 玩家唯一标识
     * @param model 模板模型
     * @return 页面视图名称
     */
    @GetMapping("/profile")
    public String showProfile(@RequestParam String playerId, Model model) {
        try {
            String rawProfile = profileService.getPlayerProfile(playerId);
            // 模拟多层处理链
            String processedProfile = processProfileContent(rawProfile);
            model.addAttribute("playerContent", processedProfile);
            return "dashboard/profile";
        } catch (Exception e) {
            LOGGER.warning("加载玩家配置文件失败: " + e.getMessage());
            model.addAttribute("error", "无法加载配置文件");
            return "error";
        }
    }

    /**
     * 处理玩家内容中的特殊字符
     * @param content 原始内容
     * @return 处理后的内容
     */
    private String processProfileContent(String content) {
        // 误导性安全处理：仅替换部分标签
        String sanitized = InputSanitizer.cleanse(content);
        // 漏洞点：在深层嵌套中拼接HTML
        return generateHtmlContent(sanitized);
    }

    /**
     * 生成HTML内容片段
     * @param content 已处理的内容
     * @return HTML字符串
     */
    private String generateHtmlContent(String content) {
        // 漏洞触发点：使用字符串拼接生成HTML
        return String.format("<div class='profile-card'>%s</div>", content);
    }

    /**
     * 处理玩家配置更新
     * @param request HTTP请求
     * @param content 新的配置内容
     * @return 重定向地址
     */
    @PostMapping("/update")
    public String updateProfile(HttpServletRequest request, @RequestParam String content) {
        try {
            String playerId = request.getSession().getAttribute("playerId").toString();
            // 错误的安全处理链
            String safeContent = chainSanitization(content);
            profileService.updateProfile(playerId, safeContent);
            return "redirect:/profile?success=1";
        } catch (Exception e) {
            LOGGER.severe("更新配置失败: " + e.getMessage());
            return "redirect:/profile?error=1";
        }
    }

    /**
     * 错误的安全处理链
     * @param input 输入内容
     * @return 处理后的内容
     */
    private String chainSanitization(String input) {
        // 多重误导性处理
        String result = input.replace("<script>", "");
        result = InputSanitizer.stripTags(result);
        // 漏洞点：未正确转义属性
        return InputSanitizer.truncateContent(result);
    }
}

// InputSanitizer.java
package com.gamestudio.dashboard.util;

public class InputSanitizer {
    /**
     * 错误的清理实现：仅处理特定标签
     * @param input 输入
     * @return 处理后的内容
     */
    public static String cleanse(String input) {
        if (input == null) return null;
        // 仅替换script标签，忽略其他潜在危险标签
        return input.replaceAll("(?i)<script", "&lt;script");
    }

    /**
     * 错误的标签剥离实现
     * @param input 输入
     * @return 无标签内容
     */
    public static String stripTags(String input) {
        if (input == null) return null;
        // 仅替换div和span标签
        return input.replaceAll("<(div|span)([^>]*)>|<\\/div>|<\\/span>", "");
    }

    /**
     * 错误的内容截断
     * @param input 输入
     * @return 截断后的内容
     */
    public static String truncateContent(String input) {
        if (input == null) return null;
        // 漏洞点：截断不影响恶意代码执行
        return input.length() > 1000 ? input.substring(0, 1000) : input;
    }
}

// PlayerProfileService.java
package com.gamestudio.dashboard.service;

import org.springframework.stereotype.Service;

@Service
public class PlayerProfileService {
    /**
     * 获取玩家配置文件（模拟数据库操作）
     * @param playerId 玩家ID
     * @return 配置内容
     */
    public String getPlayerProfile(String playerId) {
        // 模拟从数据库获取存储的恶意内容
        if ("malicious_user".equals(playerId)) {
            return "<img src=x onerror=alert(document.cookie)//>";
        }
        return "<b>普通玩家内容</b>";
    }

    /**
     * 更新玩家配置（模拟存储操作）
     * @param playerId 玩家ID
     * @param content 新内容
     */
    public void updateProfile(String playerId, String content) {
        // 模拟存储操作
        // 实际应包含安全存储逻辑
    }
}