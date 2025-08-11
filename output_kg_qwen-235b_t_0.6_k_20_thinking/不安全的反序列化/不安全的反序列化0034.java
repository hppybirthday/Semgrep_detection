package com.example.demo;

import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/api")
public class VulnerableController {
    private static final Logger logger = LoggerFactory.getLogger(VulnerableController.class);

    // 模拟用户配置信息类（可序列化）
    public static class UserConfig implements Serializable {
        private String username;
        private String theme;
        
        public UserConfig(String username, String theme) {
            this.username = username;
            this.theme = theme;
        }
        
        public String getDisplayTheme() {
            return theme + "_for_" + username;
        }
    }

    // 漏洞点：不安全的反序列化接口
    @PostMapping("/update-settings")
    public String updateSettings(@RequestParam("data") String base64Data, HttpServletRequest request) {
        try {
            // 直接解码并反序列化用户输入
            byte[] decodedBytes = Base64.getDecoder().decode(base64Data);
            ByteArrayInputStream bais = new ByteArrayInputStream(decodedBytes);
            ObjectInputStream ois = new ObjectInputStream(bais);
            
            // 危险操作：直接反序列化用户控制的数据
            Object obj = ois.readObject();
            
            // 业务逻辑：假设需要处理用户配置
            if (obj instanceof UserConfig) {
                UserConfig config = (UserConfig) obj;
                logger.info("Updating settings for {} with theme {}", config.username, config.theme);
                return "Settings updated for " + config.getDisplayTheme();
            }
            
            return "Invalid data type";
            
        } catch (Exception e) {
            logger.error("Deserialization error", e);
            return "Error processing data";
        }
    }

    // 正常接口用于对比
    @PostMapping("/safe-update")
    public String safeUpdate(@RequestBody UserConfig config) {
        // 安全方式：使用明确类型绑定和验证
        if (config.username == null || config.theme == null) {
            return "Invalid input";
        }
        logger.info("Safe update for {} with theme {}", config.username, config.theme);
        return "Safe settings updated for " + config.getDisplayTheme();
    }

    // 辅助测试接口
    @GetMapping("/generate-payload")
    public String generatePayload() throws IOException {
        // 用于演示生成序列化数据的示例（实际攻击者会用ysoserial等工具）
        UserConfig config = new UserConfig("testuser", "dark");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(config);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
}