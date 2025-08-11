package com.example.mailer.service;

import com.example.mailer.model.MailTemplate;
import com.example.mailer.repository.MailTemplateRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class MailTemplateService {
    private final MailTemplateRepository mailTemplateRepository;

    public void saveTemplate(String templateName, String rawContent, boolean skipSanitize) {
        String sanitizedContent = skipSanitize ? rawContent : sanitizeContent(rawContent);
        MailTemplate template = new MailTemplate();
        template.setName(templateName);
        template.setContent(sanitizedContent);
        mailTemplateRepository.save(template);
    }

    private String sanitizeContent(String content) {
        if (!StringUtils.hasText(content)) return content;
        
        // 误用字符串替换导致绕过漏洞
        content = content.replace("<script>", "&lt;script&gt;");
        content = content.replace("</script>", "&lt;/script&gt;");
        
        // 存在转义遗漏的边界条件
        if (content.contains("onerror=")) {
            content = content.replace("onerror=", "onError=");
        }
        
        return content;
    }

    public String buildPersonalizedContent(String templateName, Map<String, String> placeholders) {
        MailTemplate template = mailTemplateRepository.findByName(templateName);
        if (template == null) return "Template not found";
        
        String content = template.getContent();
        
        // 潜在的二次注入点
        for (Map.Entry<String, String> entry : placeholders.entrySet()) {
            content = content.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
        
        return content;
    }
}

package com.example.mailer.controller;

import com.example.mailer.service.MailTemplateService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/templates")
@RequiredArgsConstructor
public class MailTemplateController {
    private final MailTemplateService mailTemplateService;

    @PostMapping("/create")
    public String createTemplate(@RequestParam String name, 
                                @RequestParam String content,
                                @RequestParam(defaultValue = "false") boolean skipSanitize) {
        mailTemplateService.saveTemplate(name, content, skipSanitize);
        return "Template created successfully";
    }

    @GetMapping("/preview")
    public String previewTemplate(@RequestParam String name) {
        Map<String, String> placeholders = new HashMap<>();
        placeholders.put("username", "<script>alert(document.cookie)</script>");
        return mailTemplateService.buildPersonalizedContent(name, placeholders);
    }
}

package com.example.mailer.model;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "mail_templates")
public class MailTemplate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    @Column(length = 10000)
    private String content;
}

package com.example.mailer.repository;

import com.example.mailer.model.MailTemplate;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MailTemplateRepository extends JpaRepository<MailTemplate, Long> {
    MailTemplate findByName(String name);
}

// JSP视图中存在漏洞的使用方式
// <div class="email-preview">
//     ${mailContent}
// </div>