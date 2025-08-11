import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.annotation.WebServlet;

@WebServlet("/crawl")
public class VulnerableCrawler extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws IOException, ServletException {
        
        String targetUrl = request.getParameter("url");
        String crawledContent = simulateCrawl(targetUrl);
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><head><title>Crawler</title></head><body>");
        out.println("<h1>Crawled Content for: " + targetUrl + "</h1>");
        out.println("<div>" + crawledContent + "</div>");
        out.println("<form action=\\"/crawl\\" method=\\"get\\">");
        out.println("<input type=\\"text\\" name=\\"url\\" value=\\"" + targetUrl + "\\" />");
        out.println("<input type=\\"submit\\" value=\\"Crawl URL\\" />");
        out.println("</form>");
        out.println("</body></html>");
        out.close();
    }

    private String simulateCrawl(String url) {
        return "<script>alert('XSS');</script><p>Malicious content from " + url + "</p>";
    }
}