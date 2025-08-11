import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.*;

// 元编程风格的网络爬虫框架
public class VulnerableCrawler {
    private static final String BASE_PATH = "/var/www/html/plugins/configs/";
    
    // 动态加载插件配置的存储服务
    public static class StorageService {
        // 元编程风格的文件存储方法
        public void store(String path, byte[] content) throws Exception {
            // 路径遍历漏洞点：直接拼接用户输入
            File targetFile = new File(BASE_PATH + path);
            if (!targetFile.getCanonicalPath().startsWith(BASE_PATH)) {
                throw new SecurityException("非法路径访问");
            }
            Files.write(targetFile.toPath(), content);
        }

        // 存在漏洞的文件删除方法
        public void delete(String path) throws Exception {
            File targetFile = new File(BASE_PATH + path);
            if (!targetFile.getCanonicalPath().startsWith(BASE_PATH)) {
                throw new SecurityException("非法路径访问");
            }
            Files.delete(targetFile.toPath());
        }
    }

    // 动态解析URL的爬虫引擎
    public static class CrawlerEngine {
        // 元编程风格的下载方法
        public byte[] download(String urlString) throws Exception {
            URL url = new URL(urlString);
            return readStream(url.openStream());
        }

        private byte[] readStream(InputStream is) throws IOException {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[1024];
            while ((nRead = is.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            return buffer.toByteArray();
        }
    }

    // 插件管理接口
    public static class PluginManager {
        private final StorageService storage = new StorageService();
        private final CrawlerEngine crawler = new CrawlerEngine();

        // 存在漏洞的插件配置保存方法
        public void saveRemoteConfig(String pluginId, String remoteUrl) throws Exception {
            byte[] config = crawler.download(remoteUrl);
            // 危险的路径拼接：用户输入未净化
            storage.store(pluginId + "/config.yaml", config);
        }

        // 存在漏洞的插件删除方法
        public void deletePlugin(String pluginPath) throws Exception {
            storage.delete(pluginPath + "/config.yaml");
        }
    }

    public static void main(String[] args) {
        try {
            PluginManager pm = new PluginManager();
            // 模拟用户输入
            String pluginId = "../../../../../tmp/malicious";
            String remoteUrl = "file:///etc/passwd"; // 恶意文件下载
            
            // 触发路径遍历漏洞
            pm.saveRemoteConfig(pluginId, remoteUrl);
            System.out.println("配置文件保存成功");
            
            // 附加的漏洞触发点
            pm.deletePlugin("../../../../../tmp");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}