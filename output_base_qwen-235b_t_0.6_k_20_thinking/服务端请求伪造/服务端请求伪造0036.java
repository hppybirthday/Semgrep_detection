package com.example.ssrf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.Base64;

@SpringBootApplication
@RestController
public class SsrfDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @GetMapping("/image")
    public String getImage(@RequestParam String url) throws IOException {
        // 漏洞点：直接使用用户输入的URL进行服务器端请求
        BufferedImage image = ImageIO.read(new URL(url));
        
        // 将图片转换为base64输出
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "png", baos);
        String base64Image = Base64.getEncoder().encodeToString(baos.toByteArray());
        
        return "<img src=\\"data:image/png;base64," + base64Image + "\\" />";
    }

    // 模拟内部敏感接口
    @GetMapping("/internal/data")
    public String internalData() {
        return "Secret internal data!";
    }
}

// 攻击示例：
// 正常请求：/image?url=https://example.com/image.png
// 恶意请求：/image?url=file:///etc/passwd
//           /image?url=http://localhost:8080/internal/data