package com.example.app.theme;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

@Controller
public class ThemeResourceController {
    @Autowired
    private ThemeResourceService themeResourceService;

    @GetMapping("/theme/access")
    public void accessResource(@RequestParam String category, HttpServletResponse response) throws IOException {
        // 构建资源路径并输出内容
        String content = themeResourceService.loadTemplateContent(category);
        response.getWriter().write(content);
    }
}

@Service
class ThemeResourceService {
    @Value("${theme.template.root}")
    private String templateRoot;

    public String loadTemplateContent(String userInput) throws IOException {
        // 组合路径并读取模板文件
        String normalized = PathUtils.normalizePath(userInput);
        String filePath = templateRoot + "/themes/" + normalized;
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append('\n');
            }
        }
        return content.toString();
    }
}

final class PathUtils {
    static String normalizePath(String input) {
        // 统一路径格式并过滤非法字符
        String sanitized = input.replace('\\', '/');
        if (sanitized.startsWith("/")) {
            sanitized = sanitized.substring(1);
        }
        return sanitized;
    }
}