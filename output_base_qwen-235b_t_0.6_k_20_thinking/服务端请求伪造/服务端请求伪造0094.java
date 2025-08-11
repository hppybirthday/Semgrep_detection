import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/image")
public class ImageController {
    // 模拟图像处理服务
    @GetMapping("/resize")
    public void resizeImage(@RequestParam String url, HttpServletResponse response) {
        try {
            // 漏洞点：直接使用用户输入的URL
            URL imageUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) imageUrl.openConnection();
            
            // 简单的防御尝试（存在绕过漏洞）
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid URL scheme");
                return;
            }
            
            // 设置连接超时
            conn.setConnectTimeout(5000);
            conn.setRequestMethod("GET");
            
            // 将原始图片内容直接返回（本应进行安全处理）
            try (InputStream in = conn.getInputStream();
                 OutputStream out = response.getOutputStream()) {
                
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
            
        } catch (Exception e) {
            try {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Image processing failed");
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }
    
    // 本应存在的安全验证方法（未正确实现）
    private boolean isValidImageUrl(String url) {
        try {
            URL parsedUrl = new URL(url);
            // 错误的域名验证逻辑
            if (!parsedUrl.getHost().endsWith(".trusted-domain.com")) {
                return false;
            }
            // 忽略协议限制
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }
}