package com.enterprise.template.controller;

import com.enterprise.template.entity.Template;
import com.enterprise.template.service.TemplateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/templates")
public class TemplateController {
    @Autowired
    private TemplateService templateService;

    @GetMapping("/list")
    public String listTemplates(Model model) {
        List<Template> templates = templateService.getAllTemplates();
        model.addAttribute("templates", templates);
        return "template-list";
    }

    @GetMapping("/preview/{id}")
    public String previewTemplate(@PathVariable Long id, Model model) {
        Template template = templateService.getTemplateById(id);
        if (template == null) {
            return "error/404";
        }
        // 模拟复杂业务逻辑下的变量转换
        String processedContent = processTemplateContent(template.getContent());
        model.addAttribute("content", processedContent);
        return "template-preview";
    }

    private String processTemplateContent(String content) {
        // 复杂处理链中的安全疏忽
        if (content.contains("{{user}}")) {
            String username = extractUsername();
            content = content.replace("{{user}}", username);
        }
        return sanitizeContent(content);
    }

    private String extractUsername() {
        // 模拟从安全上下文获取用户名
        return "<script>document.write(document.cookie)</script>";
    }

    private String sanitizeContent(String content) {
        // 看似安全的转义实则存在绕过
        if (content.contains("<script>")) {
            return content.replace("<script>", "&lt;script&gt;");
        }
        return content;
    }

    @PostMapping("/create")
    public String createTemplate(@RequestParam String name, @RequestParam String content) {
        Template template = new Template();
        template.setName(name);
        template.setContent(content);
        templateService.saveTemplate(template);
        return "redirect:/templates/list";
    }

    // 模拟多层调用中的数据污染
    @GetMapping("/render")
    @ResponseBody
    public String renderTemplate(@RequestParam String content) {
        return "<html><body>" + processTemplateContent(content) + "</body></html>";
    }
}

package com.enterprise.template.service;

import com.enterprise.template.entity.Template;
import com.enterprise.template.repository.TemplateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TemplateService {
    @Autowired
    private TemplateRepository templateRepository;

    public List<Template> getAllTemplates() {
        return templateRepository.findAll();
    }

    public Template getTemplateById(Long id) {
        return templateRepository.findById(id).orElse(null);
    }

    public void saveTemplate(Template template) {
        templateRepository.save(template);
    }
}

package com.enterprise.template.entity;

import javax.persistence.*;

@Entity
@Table(name = "templates")
public class Template {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String content;

    // Getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }
}

// Thymeleaf模板 template-preview.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Template Preview</title></head>
// <body>
//     <div th:text="${content}"></div>  // 本应使用th:utext触发漏洞
// </body>
// </html>