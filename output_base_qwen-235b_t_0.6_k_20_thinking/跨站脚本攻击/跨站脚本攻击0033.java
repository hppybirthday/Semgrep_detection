import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/crawl")
public class VulnerableCrawler extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String targetUrl = request.getParameter("url");
        String result = "";
        
        if (targetUrl != null && !targetUrl.isEmpty()) {
            try {
                HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .build();
                
                HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
                result = processResponse(httpResponse.body(), targetUrl);
            } catch (Exception e) {
                result = "Error crawling " + targetUrl + ": " + e.getMessage();
            }
        }
        
        response.setContentType("text/html");
        response.getWriter().println(
            "<html><body>" +
            "<h2>Crawl Result for: " + targetUrl + "</h2>" + 
            "<div style='border:1px solid;padding:10px;margin:10px;white-space:pre-wrap;'>" +
            result +
            "</div>" +
            "</body></html>"
        );
    }

    private String processResponse(String content, String url) {
        // 模拟内容处理：截取前500字符并添加引用信息
        int endIndex = Math.min(content.length(), 500);
        return content.substring(0, endIndex) + 
               "<br><br><small>Processed from: " + url + "</small>";
    }
}