import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

@SpringBootApplication
public class SsrfVulnerableApp {

    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApp.class, args);
    }

    @Controller
    public class ImageController {

        @GetMapping("/image")
        public String getImage(@RequestParam("url") String imageUrl, Model model) {
            StringBuilder content = new StringBuilder();
            try {
                // 漏洞点：直接使用用户输入的URL构建请求
                URL targetUrl = new URL(imageUrl);
                HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
                connection.setRequestMethod("GET");

                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream())
                );
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line);
                }
                reader.close();

            } catch (IOException e) {
                content.append("Error loading image: ").append(e.getMessage());
            }

            // 模拟服务器端渲染，直接显示原始内容
            model.addAttribute("imageContent", content.toString());
            return "imageTemplate";
        }
    }
}

// Thymeleaf模板示例（实际不会出现在Java代码中）
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Image Viewer</title></head>
<body>
    <div th:utext="${imageContent}"></div>  // 危险操作：直接输出原始内容
</body>
</html>
*/