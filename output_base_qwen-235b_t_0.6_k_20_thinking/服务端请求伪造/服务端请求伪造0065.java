import java.lang.reflect.Method;
import java.io.*;
import java.net.*;

interface WebCrawler {
    void crawl(String url) throws Exception;
}

class CurlCrawler implements WebCrawler {
    @Override
    public void crawl(String url) throws Exception {
        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("GET");
        
        BufferedReader in = new BufferedReader(
            new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();
        
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        System.out.println(response.toString());
    }
}

class CrawlerFactory {
    public static WebCrawler createCrawler(String className) throws Exception {
        Class<?> clazz = Class.forName(className);
        return (WebCrawler) clazz.getDeclaredConstructor().newInstance();
    }
}

class ReflectionInvoker {
    public static void invokeCrawl(String className, String url) throws Exception {
        WebCrawler crawler = CrawlerFactory.createCrawler(className);
        Method method = crawler.getClass().getMethod("crawl", String.class);
        method.invoke(crawler, url);
    }
}

public class SSRFDemo {
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java SSRFDemo <crawler_class> <target_url>");
            return;
        }
        
        try {
            String className = args[0];
            String targetUrl = args[1];
            
            // 元编程特性：通过反射动态调用爬虫类
            ReflectionInvoker.invokeCrawl(className, targetUrl);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}