import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.Scanner;

/**
 * 网络爬虫文件下载器
 * 存在路径遍历漏洞的示例代码
 */
public class VulnerableWebCrawler {
    // 基础下载目录（本应受保护）
    private static final String BASE_DOWNLOAD_DIR = "/var/www/html/downloads/";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("请输入要下载的文件URL: ");
        String userInput = scanner.nextLine();
        
        try {
            downloadFile(userInput);
        } catch (Exception e) {
            System.err.println("下载失败: " + e.getMessage());
        }
    }

    /**
     * 下载并保存文件
     * @param fileUrl 用户输入的文件URL
     * @throws Exception
     */
    public static void downloadFile(String fileUrl) throws Exception {
        URL url = new URL(fileUrl);
        String path = url.getPath();  // 直接获取URL路径部分
        
        // 漏洞点：直接拼接路径导致路径遍历
        String targetPath = BASE_DOWNLOAD_DIR + path;
        
        System.out.println("保存路径: " + targetPath);
        
        // 创建父目录（如果不存在）
        Files.createDirectories(Paths.get(targetPath).getParent());
        
        // 模拟下载过程
        try (InputStream in = url.openStream();
             OutputStream out = new FileOutputStream(targetPath)) {
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
        
        System.out.println("文件下载成功！");
    }

    /**
     * 清理下载目录（模拟定时任务）
     */
    public static void cleanupDownloads() {
        try {
            Files.walk(Paths.get(BASE_DOWNLOAD_DIR))
                .filter(path -> !Files.isDirectory(path))
                .forEach(path -> {
                    try {
                        Files.delete(path);
                    } catch (Exception e) {
                        System.err.println("清理失败: " + e.getMessage());
                    }
                });
        } catch (Exception e) {
            System.err.println("清理过程出错: " + e.getMessage());
        }
    }
}