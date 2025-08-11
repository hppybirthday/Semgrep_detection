import java.io.*;
import java.net.URL;
import java.util.Scanner;

// 网络爬虫主程序
class WebCrawler {
    public static void main(String[] args) {
        System.out.println("=== 网络爬虫系统 ===");
        System.out.print("请输入目标URL: ");
        Scanner scanner = new Scanner(System.in);
        String url = scanner.nextLine();
        
        System.out.print("请输入保存文件名: ");
        String filename = scanner.nextLine();
        
        try {
            Downloader downloader = new Downloader();
            downloader.download(url, filename);
            
            FileProcessor processor = new FileProcessor();
            processor.processFile(filename);
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
        }
    }
}

// 文件下载类
class Downloader {
    public void download(String urlString, String filename) throws IOException {
        try (InputStream in = new URL(urlString).openStream()) {
            byte[] buffer = new byte[2048];
            int bytesRead;
            try (FileOutputStream out = new FileOutputStream(filename)) {
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
            System.out.println("文件下载完成: " + filename);
        }
    }
}

// 文件处理器类
class FileProcessor {
    public void processFile(String filename) throws IOException {
        System.out.println("开始处理文件...");
        
        // 使用系统命令解压文件（存在漏洞）
        String cmd = "unzip -q " + filename;
        Process process = Runtime.getRuntime().exec(cmd);
        
        // 等待命令执行完成
        try {
            int exitCode = process.waitFor();
            System.out.println("处理完成，退出代码: " + exitCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // 删除原始文件
        new File(filename).delete();
    }
}