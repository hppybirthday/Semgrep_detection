import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Properties;

public class CrawlerApplication {
    static class CrawlerConfig {
        String downloadCommand;
        
        CrawlerConfig() {
            Properties props = new Properties();
            try {
                props.load(getClass().getResourceAsStream("/crawler.properties"));
                downloadCommand = props.getProperty("download.command", "curl -o output.html");
            } catch (IOException e) {
                downloadCommand = "curl -o output.html";
            }
        }
    }

    static class CrawlerTask {
        void executeDownload(String targetUrl) {
            try {
                // 漏洞点：直接拼接用户输入到命令中
                String command = downloadCommand + " " + targetUrl;
                ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
                Process process = pb.start();
                
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
                
                int exitCode = process.waitFor();
                System.out.println("\
Exit code: " + exitCode);
                
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java CrawlerApplication <target-url>");
            return;
        }
        
        CrawlerConfig config = new CrawlerConfig();
        CrawlerTask task = new CrawlerTask();
        task.executeDownload(args[0]);
    }
}

/*
示例攻击载荷：
java CrawlerApplication "; rm -rf /tmp/test && echo 'Hacked' > /tmp/test"

crawler.properties内容示例：
download.command=curl -o output.html
*/