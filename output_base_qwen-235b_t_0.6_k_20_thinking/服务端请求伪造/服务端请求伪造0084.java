package com.example.demo;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import javax.imageio.ImageIO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
public class ImageProcessingController {
    private static final Logger logger = LoggerFactory.getLogger(ImageProcessingController.class);
    private static final String URL_REGEX = "^https?://.*$";

    @GetMapping("/process-image")
    public String processImage(@RequestParam("imageUrl") String imageUrl, Model model) {
        try {
            // 漏洞点：不安全的URL验证
            if (!imageUrl.matches(URL_REGEX)) {
                model.addAttribute("error", "Invalid URL format");
                return "error";
            }

            URL url = new URL(imageUrl);
            URLConnection connection = url.openConnection();
            
            // 模拟图像处理
            try (InputStream is = connection.getInputStream()) {
                BufferedImage image = ImageIO.read(is);
                if (image == null) {
                    model.addAttribute("error", "Invalid image format");
                    return "error";
                }

                // 计算图像特征
                int width = image.getWidth();
                int height = image.getHeight();
                Image scaledImage = image.getScaledInstance(100, 100, Image.SCALE_DEFAULT);
                
                model.addAttribute("width", width);
                model.addAttribute("height", height);
                return "image-result";
            }
        } catch (IOException e) {
            logger.error("Image processing failed: {}", e.getMessage());
            model.addAttribute("error", "Failed to process image");
            return "error";
        } catch (Exception e) {
            logger.warn("Potential SSRF attempt detected: {}", e.getMessage());
            model.addAttribute("error", "Invalid image source");
            return "error";
        }
    }

    // 本应存在的安全校验方法（未被调用）
    private boolean isSafeUrl(String url) {
        // 理想情况下应包含IP白名单、协议限制等检查
        return url.startsWith("https://trusted-cdn.com/");
    }
}