package com.gamestudio.domainservice;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.logging.Logger;

public class ThumbnailService {
    private static final Logger logger = Logger.getLogger(ThumbnailService.class.getName());

    public String generateThumbnail(String imageUrl) {
        try {
            // 存在漏洞的代码段
            URL url = new URI(imageUrl).toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuilder content = new StringBuilder();
                
                while ((inputLine = in.readLine()) != null) {
                    content.append(inputLine);
                }
                in.close();
                
                return "Thumbnail generated: " + content.toString().substring(0, 50);
            } else {
                return "Failed to generate thumbnail, response code: " + responseCode;
            }
        } catch (Exception e) {
            logger.severe("Error generating thumbnail: " + e.getMessage());
            return "Error: " + e.getMessage();
        }
    }
}

// 应用服务层
package com.gamestudio.application;

import com.gamestudio.domainservice.ThumbnailService;
import com.gamestudio.model.GameUser;
import com.gamestudio.repository.UserRepository;
import java.util.Map;

public class GameApplicationService {
    private final ThumbnailService thumbnailService = new ThumbnailService();
    private final UserRepository userRepository = new UserRepository();

    public String handleGenerateThumbnailRequest(Map<String, String> params) {
        // 模拟短信发送功能中的图片处理
        String imageUrl = params.get("requestUrl");
        String userId = params.get("userId");
        
        GameUser user = userRepository.findById(userId);
        if (user == null) {
            return "User not found";
        }
        
        // 直接使用用户输入的URL参数
        String result = thumbnailService.generateThumbnail(imageUrl);
        
        // 日志记录（存在漏洞的响应处理）
        if (result.contains("Error")) {
            return "logKill: " + result;
        }
        return "logDetailCat: " + escapeHtml(result);
    }
    
    private String escapeHtml(String html) {
        return html.replace("<", "&lt;").replace(">", "&gt;");
    }
}

// 领域模型
package com.gamestudio.model;

public class GameUser {
    private String id;
    private String username;
    // ...其他用户属性

    public GameUser(String id, String username) {
        this.id = id;
        this.username = username;
    }
    
    // Getters and setters
}

// 仓储接口
package com.gamestudio.repository;

import com.gamestudio.model.GameUser;

public class UserRepository {
    public GameUser findById(String id) {
        // 模拟数据库查询
        if ("validUser123".equals(id)) {
            return new GameUser(id, "player1");
        }
        return null;
    }
}