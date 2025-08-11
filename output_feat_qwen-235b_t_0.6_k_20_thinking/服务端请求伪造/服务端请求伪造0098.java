import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.*;
import java.io.*;

@RestController
@RequestMapping("/api/chat")
public class ChatController {
    private final RestTemplate restTemplate = new RestTemplate();

    @PostMapping("/upload")
    public String uploadImage(@RequestBody UploadFromUrlRequest request) {
        try {
            String imageUrl = request.getUrl();
            // 模拟下载图片处理
            String response = restTemplate.getForObject(imageUrl, String.class);
            // 简化处理：直接返回响应摘要
            return "{\\"status\\":\\"success\\",\\"size\\":\\"" + response.length() + "\\"}";
        } catch (Exception e) {
            return "{\\"status\\":\\"error\\",\\"message\\":\\"Invalid image URL\\"}";
        }
    }
}

class UploadFromUrlRequest {
    private String url;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}

// 模拟的聊天消息类
class ChatMessage {
    private String content;
    private String attachmentUrl;

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getAttachmentUrl() {
        return attachmentUrl;
    }

    public void setAttachmentUrl(String attachmentUrl) {
        this.attachmentUrl = attachmentUrl;
    }
}