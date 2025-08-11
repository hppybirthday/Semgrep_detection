import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.imageio.ImageIO;

class ThumbnailGenerator {
    public BufferedImage getThumbnail(String imageUrl) throws IOException {
        URL url = new URL(imageUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
            return ImageIO.read(connection.getInputStream());
        }
        throw new IOException("Failed to load image");
    }
}

class GameResourceLoader {
    private ThumbnailGenerator thumbnailGenerator = new ThumbnailGenerator();
    
    public void loadExternalResource(String resourceUrl) {
        try {
            BufferedImage thumb = thumbnailGenerator.getThumbnail(resourceUrl);
            System.out.println("Thumbnail loaded: " + thumb.getWidth() + "x" + thumb.getHeight());
        } catch (Exception e) {
            System.err.println("Resource load failed: " + e.getMessage());
        }
    }
}

public class GenDatasourceConfServiceImpl {
    // 模拟桌面游戏配置检查功能
    public boolean checkDataSource(String param) {
        GameResourceLoader loader = new GameResourceLoader();
        
        // 漏洞点：直接使用用户输入构造URL
        loader.loadExternalResource("https://gamecdn.com/thumbs/" + param + ".png");
        
        // 模拟敏感操作
        return true;
    }
    
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java GenDatasourceConfServiceImpl <param>");
            return;
        }
        
        GenDatasourceConfServiceImpl service = new GenDatasourceConfServiceImpl();
        boolean result = service.checkDataSource(args[0]);
        System.out.println("Check result: " + result);
    }
}