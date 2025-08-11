package com.example.app.template;

import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.templateresolver.SpringResourceTemplateResolver;
import org.springframework.ui.Model;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/templates")
public class TemplateController {
    @Autowired
    private TemplateService templateService;

    @PostMapping("/save")
    public String saveTemplate(@RequestParam String content) {
        // 校验模板长度（业务规则）
        if (content.length() > 1000) {
            return "模板内容过长";
        }
        templateService.save(content);
        return "保存成功";
    }

    @GetMapping("/render")
    public String renderTemplate(Model model) {
        String storedContent = templateService.get();
        // 构建模板上下文
        Map<String, Object> context = new HashMap<>();
        context.put("userContent", storedContent);
        return templateService.render("user_template", context);
    }
}

@Service
class TemplateService {
    private String currentTemplate = "默认模板内容";
    private final TemplateEngine templateEngine;

    public TemplateService(SpringResourceTemplateResolver templateResolver) {
        this.templateEngine = new TemplateEngine();
        this.templateEngine.setTemplateResolver(templateResolver);
    }

    void save(String content) {
        // 存储用户模板内容
        currentTemplate = content;
    }

    String get() {
        return currentTemplate;
    }

    String render(String templateName, Map<String, Object> context) {
        Context thymeleafContext = new Context();
        thymeleafContext.setVariables(context);
        // 使用Thymeleaf渲染用户内容
        return templateEngine.process(templateName, thymeleafContext);
    }
}

// Thymeleaf配置类（简化版）
// @Configuration
// class ThymeleafConfig {
//     @Bean
//     SpringResourceTemplateResolver templateResolver() {
//         SpringResourceTemplateResolver resolver = new SpringResourceTemplateResolver();
//         resolver.setPrefix("classpath:/templates/");
//         resolver.setSuffix(".html");
//         return resolver;
//     }
// }