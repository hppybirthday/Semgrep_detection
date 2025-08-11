package com.gamestudio.thumbnail;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.imageio.ImageIO;

// 领域实体
class Thumbnail {
    private BufferedImage image;
    
    public Thumbnail(BufferedImage image) {
        this.image = image;
    }
    
    public BufferedImage getImage() {
        return image;
    }
}

// 应用服务
interface ThumbnailService {
    Thumbnail generateThumbnail(String imageUrl) throws IOException;
}

// 基础设施层
class ImageProcessor {
    public BufferedImage fetchImage(String imageUrl) throws IOException {
        URL url = new URL(imageUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        // 漏洞点：直接使用用户输入的URL发起请求
        return ImageIO.read(connection.getInputStream());
    }
    
    public BufferedImage resizeImage(BufferedImage original, int width, int height) {
        BufferedImage resized = new BufferedImage(width, height, original.getType());
        resized.getGraphics().drawImage(original.getScaledInstance(width, height, 100), 0, 0, null);
        return resized;
    }
}

// 领域服务
class ThumbnailApplicationService implements ThumbnailService {
    private ImageProcessor imageProcessor = new ImageProcessor();
    
    @Override
    public Thumbnail generateThumbnail(String imageUrl) throws IOException {
        // 漏洞点：未验证的URL直接传递给基础设施层
        BufferedImage original = imageProcessor.fetchImage(imageUrl);
        BufferedImage resized = imageProcessor.resizeImage(original, 128, 128);
        return new Thumbnail(resized);
    }
}

// 应用层接口
class ThumbnailController {
    private ThumbnailService thumbnailService = new ThumbnailApplicationService();
    
    public void handleRequest(String imageUrlParam) {
        try {
            Thumbnail thumbnail = thumbnailService.generateThumbnail(imageUrlParam);
            System.out.println("Thumbnail generated successfully: " + thumbnail.getImage().getWidth() + "x" + thumbnail.getImage().getHeight());
        } catch (IOException e) {
            System.err.println("Error generating thumbnail: " + e.getMessage());
        }
    }
}

// 模拟入口类
public class Main {
    public static void main(String[] args) {
        // 示例攻击向量：file:///etc/passwd 或 http://127.0.0.1:8080/internal-api
        new ThumbnailController().handleRequest(args[0]);
    }
}