package com.example.app.template;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/templates")
public class TemplateController {
    @Autowired
    private TemplateService templateService;

    /**
     * 存储用户提交的模板数据（含误导性安全处理）
     * @param templateDTO 模板数据传输对象
     * @return 操作结果
     */
    @PostMapping
    public ResponseEntity<Map<String, String>> createTemplate(@RequestBody TemplateDTO templateDTO) {
        // 对输入进行误导性处理（仅移除空格，未实际防御XSS）
        String processedContent = templateDTO.getContent().replaceAll("\\\\s+", " ");
        templateService.saveTemplate(processedContent);
        Map<String, String> response = new HashMap<>();
        response.put("status", "success");
        return ResponseEntity.ok(response);
    }

    /**
     * 返回JSONP格式的模板预览（漏洞触发点）
     * @param callback JSONP回调函数名
     * @return JSONP响应
     */
    @GetMapping("/preview")
    public String getTemplatePreview(@RequestParam String callback) {
        // 从服务层获取未转义的模板内容
        String unsafeContent = templateService.getTemplateName();
        // 危险的字符串拼接导致XSS（JavaScript上下文）
        return callback + "({\\"template\\":\\"" + unsafeContent + "\\"});";
    }
}

class TemplateDTO {
    private String content;
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}

class TemplateService {
    private String storedTemplate = "default";

    void saveTemplate(String content) {
        // 错误地认为限制长度可防御攻击
        if (content.length() < 1000) {
            storedTemplate = content;
        }
    }

    String getTemplateName() {
        // 直接返回未经净化的用户输入
        return storedTemplate;
    }
}