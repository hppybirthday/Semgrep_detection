import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Scanner;

interface Crawler {
    void fetch(String url);
}

public class VulnerableCrawler implements InvocationHandler {
    private Object target;

    public VulnerableCrawler(Object target) {
        this.target = target;
    }

    public static Object newInstance(Object target) {
        return Proxy.newProxyInstance(
            target.getClass().getClassLoader(),
            target.getClass().getInterfaces(),
            new VulnerableCrawler(target)
        );
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (args != null && args.length > 0 && args[0] instanceof String) {
            String input = (String) args[0];
            // 模拟爬虫处理URL时的危险拼接
            String cmd = "curl -s \\"" + input + "\\" | grep -A 10 \\"<title>\\"";
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
            Process process = pb.start();
            java.io.InputStream is = process.getInputStream();
            java.util.Scanner s = new Scanner(is).useDelimiter("\\\\A");
            System.out.println("Response: " + (s.hasNext() ? s.next() : ""));
        }
        return null;
    }

    public static void main(String[] args) {
        Crawler crawler = (Crawler) newInstance(new Crawler() {
            @Override
            public void fetch(String url) {}
        });

        System.out.print("Enter URL to crawl: ");
        Scanner scanner = new Scanner(System.in);
        String userInput = scanner.nextLine();
        
        // 危险调用链
        try {
            Method method = Crawler.class.getMethod("fetch", String.class);
            method.invoke(crawler, userInput);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}