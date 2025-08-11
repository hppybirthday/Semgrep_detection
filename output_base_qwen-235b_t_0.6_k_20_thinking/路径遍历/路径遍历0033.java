import java.io.*;
import java.net.*;
import java.nio.file.*;

public class WebCrawler {
    private String downloadDir;

    public WebCrawler(String downloadDir) {
        this.downloadDir = downloadDir;
    }

    public void downloadPage(String urlString) throws IOException {
        try {
            URL url = new URL(urlString);
            String path = url.getPath();
            
            // Vulnerable path construction
            String localPath = downloadDir + File.separator + "pages" + path;
            
            // Create necessary directories
            Files.createDirectories(Paths.get(localPath).getParent());
            
            // Simulate downloading content
            try (BufferedReader reader = new BufferedReader(
                 new InputStreamReader(url.openStream()));
                 BufferedWriter writer = new BufferedWriter(
                 new FileWriter(localPath))) {
                
                String line;
                while ((line = reader.readLine()) != null) {
                    writer.write(line);
                    writer.newLine();
                }
            }
            System.out.println("Downloaded to: " + localPath);
            
        } catch (MalformedURLException e) {
            System.err.println("Invalid URL: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java WebCrawler <url>");
            return;
        }
        
        try {
            // Example vulnerable usage: 
            // java WebCrawler http://example.com/../../../../etc/passwd
            WebCrawler crawler = new WebCrawler("/var/www/html");
            crawler.downloadPage(args[0]);
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}