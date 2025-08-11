package com.crm.core.ad;

import com.crm.service.AdSanitizer;
import com.crm.service.AdService;
import com.crm.util.LoggerUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * 广告内容管理控制器
 * 处理广告创建与展示流程中的XSS漏洞场景
 */
@Controller
@RequestMapping("/ad")
public class AdManagementController {
    
    @Autowired
    private AdService adService;
    
    @Autowired
    private AdSanitizer adSanitizer;
    
    private static final String AD_TEMPLATE = "<div class='ad-content'>%s</div>";

    /**
     * 创建广告内容（存储型XSS入口）
     */
    @PostMapping("/create")
    public String createAd(@RequestParam("content") String content, Model model) {
        // 模拟业务流程中的多层处理
        String processedContent = preprocessContent(content);
        String sanitized = adSanitizer.sanitize(processedContent);
        
        // 记录日志时直接拼接原始内容（漏洞点1）
        LoggerUtil.logAccess("AdCreated: " + content);
        
        // 存储到数据库
        adService.saveAd(sanitized);
        model.addAttribute("status", "Ad created successfully");
        return "redirect:/ad/list";
    }
    
    /**
     * 展示广告内容（XSS触发点）
     */
    @GetMapping("/view/{id}")
    public String viewAd(@PathVariable("id") Long id, Model model, HttpServletRequest request) {
        String rawContent = adService.getAdContent(id);
        
        // 构造富文本上下文（漏洞点2）
        String htmlContent = String.format(AD_TEMPLATE, rawContent);
        
        // 模拟邮件内容拼接场景（漏洞点3）
        if (request.getParameter("email") != null) {
            String emailBody = buildEmailContent(rawContent);
            model.addAttribute("emailPreview", emailBody);
        }
        
        model.addAttribute("adContent", htmlContent);
        return "ad/view";
    }
    
    /**
     * 构建HTML邮件内容（二次注入场景）
     */
    private String buildEmailContent(String content) {
        // 未对内容进行HTML编码
        return "<html><body>广告内容：" + content + "</body></html>";
    }
    
    /**
     * 预处理广告内容（混淆逻辑）
     * 实际未进行有效过滤
     */
    private String preprocessContent(String content) {
        if (content == null) return "";
        
        // 看似安全的替换逻辑（可被绕过）
        content = content.replace("<script", "&lt;script");
        content = content.replace("script>", "script&gt;");
        
        // 隐藏的拼接漏洞
        return new StringBuilder(content).toString();
    }
}

// 模拟不安全的广告清理服务
class AdSanitizer {
    /**
     * 不充分的清理逻辑（存在绕过可能）
     */
    public String sanitize(String input) {
        if (input == null) return null;
        
        // 仅替换小写标签（忽略大小写变体）
        String result = input.replace("<script>", "").replace("</script>", "");
        
        // 引入其他漏洞载体
        return result.replace("img src", "img xss=1 src");
    }
}

// 模拟日志工具类（存在注入点）
class LoggerUtil {
    private static final Map<String, String> LOG_BUFFER = new HashMap<>();
    
    public static void logAccess(String message) {
        // 直接拼接原始内容到日志（存储型XSS潜在点）
        String logEntry = String.format("[%s] %s", System.currentTimeMillis(), message);
        LOG_BUFFER.put("last_log", logEntry);
    }
}

// 广告实体类
record AdEntity(Long id, String content) {}

// 广告业务服务接口
class AdService {
    private String storage = "";
    
    public void saveAd(String content) {
        storage = content; // 简化存储逻辑
    }
    
    public String getAdContent(Long id) {
        return storage; // 简化读取逻辑
    }
}