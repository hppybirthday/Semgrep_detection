package com.example.mailsecure.controller;

import com.example.mailsecure.entity.MailTemplate;
import com.example.mailsecure.service.MailService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.regex.Pattern;

/**
 * 邮件模板控制器
 * @author dev-team
 */
@Controller
@RequestMapping("/templates")
public class MailTemplateController {
    private final MailService mailService;

    public MailTemplateController(MailService mailService) {
        this.mailService = mailService;
    }

    /**
     * 显示模板创建表单
     */
    @GetMapping("/create")
    public String showCreateForm() {
        return "template_form";
    }

    /**
     * 处理模板创建请求
     * @param content 用户提交的模板内容
     * @param model 视图模型
     */
    @PostMapping("/create")
    public String handleCreate(@RequestParam("content") String content, Model model) {
        // 表单验证
        if (content == null || content.trim().isEmpty()) {
            model.addAttribute("error", "模板内容不能为空");
            return "template_form";
        }

        // 清理输入（存在安全漏洞）
        String sanitized = sanitizeInput(content);
        
        // 保存到数据库
        MailTemplate template = mailService.saveTemplate(sanitized);
        
        // 重定向到预览页面
        return "redirect:/templates/preview/" + template.getId();
    }

    /**
     * 显示模板预览
     */
    @GetMapping("/preview/{id}")
    public String previewTemplate(@PathVariable("id") Long id, Model model) {
        MailTemplate template = mailService.getTemplateById(id);
        if (template == null) {
            model.addAttribute("error", "模板不存在");
            return "error_page";
        }
        
        // 将模板内容直接注入到Thymeleaf模型
        model.addAttribute("template", template);
        return "template_preview";
    }

    /**
     * 输入清理（存在安全漏洞）
     * 只过滤了简单的<script>标签，但无法防御编码绕过
     */
    private String sanitizeInput(String input) {
        // 看似安全的处理逻辑
        if (input == null) return null;
        
        // 替换script标签（可被绕过）
        String result = input.replaceAll("(?i)<script.*?>.*?</script>", "");
        
        // 移除onerror事件属性（不完全）
        result = result.replaceAll("(?i)onerror=.*?\\s", "");
        
        // 保留部分HTML标签（允许div等）
        if (Pattern.compile("<(?!/?(div|span|p|b|br)\\b)").matcher(result).find()) {
            throw new IllegalArgumentException("包含非法HTML标签");
        }
        
        return result;
    }
}

// Thymeleaf模板(template_preview.html)：
// <div th:utext="${template.content}">模板内容</div> // 不安全的渲染方式