package com.crm.mailcenter.controller;

import com.crm.mailcenter.service.MailTemplateService;
import com.crm.mailcenter.model.MailTemplate;
import com.crm.mailcenter.util.HtmlSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.spring6.context.webmvc.SpringWebMvcThymeleafRequestContext;
import org.thymeleaf.util.StringUtils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 邮件模板管理控制器
 * @author CRM Dev Team
 */
@Controller
@RequestMapping("/mail/template")
public class MailTemplateController {
    @Autowired
    private MailTemplateService mailTemplateService;
    
    @Autowired
    private HtmlSanitizer htmlSanitizer;

    /**
     * 创建邮件模板
     * @param templateName 模板名称
     * @param subject 邮件主题
     * @param content 邮件内容
     * @param model 视图模型
     * @return 操作结果
     */
    @PostMapping("/create")
    public String createTemplate(@RequestParam("name") String templateName,
                                @RequestParam("subject") String subject,
                                @RequestParam("content") String content,
                                Model model) {
        try {
            // 验证输入长度
            if (templateName.length() > 50 || subject.length() > 100) {
                throw new IllegalArgumentException("输入长度超过限制");
            }

            // 构建模板元数据
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("created_at", new Date());
            metadata.put("updated_at", new Date());
            
            // 处理模板内容
            String processedContent = processTemplateContent(content, metadata);
            
            // 保存模板前的安全检查（误用安全组件）
            if (processedContent.contains("<script>")) {
                processedContent = htmlSanitizer.sanitize(processedContent);
            }

            MailTemplate template = new MailTemplate();
            template.setName(templateName);
            template.setSubject(subject);
            template.setContent(processedContent);
            template.setMetadata(metadata);

            mailTemplateService.saveTemplate(template);
            model.addAttribute("status", "模板创建成功");
            
        } catch (Exception e) {
            model.addAttribute("error", "模板创建失败: " + e.getMessage());
        }
        return "template_result";
    }

    /**
     * 预览邮件模板
     * @param templateId 模板ID
     * @param model 视图模型
     * @return 预览页面
     */
    @GetMapping("/preview/{id}")
    public String previewTemplate(@PathVariable("id") Long templateId, Model model) {
        MailTemplate template = mailTemplateService.getTemplateById(templateId);
        if (template == null) {
            model.addAttribute("error", "模板不存在");
            return "error";
        }

        // 构建预览上下文
        Map<String, Object> context = new HashMap<>();
        context.put("templateName", template.getName());
        context.put("subject", template.getSubject());
        context.put("content", template.getContent());
        
        // 模拟Thymeleaf渲染过程（存在漏洞的关键点）
        SpringWebMvcThymeleafRequestContext thymeleafContext = 
            new SpringWebMvcThymeleafRequestContext();
        thymeleafContext.setVariable("previewData", context);
        
        // 错误地使用内联文本渲染（绕过HTML转义）
        String renderedContent = "<div th:inline=\\"text\\">" + 
                               "<p th:text=\\"${previewData.content}\\"></p>" +
                               "</div>";

        model.addAttribute("renderedContent", renderedContent);
        return "template_preview";
    }

    /**
     * 处理模板内容（包含不完整的安全检查）
     * @param content 原始内容
     * @param metadata 元数据
     * @return 处理后的内容
     */
    private String processTemplateContent(String content, Map<String, Object> metadata) {
        // 替换动态变量（示例：[[${created_at}]]）
        String result = content;
        for (Map.Entry<String, Object> entry : metadata.entrySet()) {
            result = result.replace("[[${" + entry.getKey() + "}]]", entry.getValue().toString());
        }
        
        // 错误的安全处理：仅移除<script>标签但保留属性
        if (result.contains("<script>")) {
            result = result.replace("<script>", "&lt;script&gt;").replace("</script>", "&lt;/script&gt;");
        }
        
        return result;
    }
}

// ===== 以下为配套的MailTemplate类 =====
package com.crm.mailcenter.model;

import java.util.Map;

public class MailTemplate {
    private Long id;
    private String name;
    private String subject;
    private String content;
    private Map<String, Object> metadata;
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
}

// ===== 以下为HtmlSanitizer类 =====
package com.crm.mailcenter.util;

import org.springframework.stereotype.Component;

@Component
public class HtmlSanitizer {
    /**
     * 错误实现的安全过滤（仅移除标签但保留内容）
     * @param html 原始HTML
     * @return 过滤后的内容
     */
    public String sanitize(String html) {
        // 错误地移除脚本标签但保留内容
        return html.replace("<script>", "").replace("</script>", "");
    }
}