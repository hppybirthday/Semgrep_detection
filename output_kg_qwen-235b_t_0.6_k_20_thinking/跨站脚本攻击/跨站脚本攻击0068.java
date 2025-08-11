import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/search")
public class SearchServlet extends HttpServlet {
    private DataProcessor dataProcessor = new DataProcessor();
    private ReportGenerator reportGenerator = new ReportGenerator();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
        throws ServletException, IOException {
        
        String query = req.getParameter("q");
        if (query == null) query = "";
        
        List<SearchResult> results = dataProcessor.processData(query);
        String htmlReport = reportGenerator.generateReport(query, results);
        
        resp.setContentType("text/html");
        resp.getWriter().write(htmlReport);
    }
}

class DataProcessor {
    public List<SearchResult> processData(String query) {
        List<SearchResult> results = new ArrayList<>();
        if (query.contains("malicious")) {
            results.add(new SearchResult("http://example.com/malware.exe", 9.8));
        }
        results.add(new SearchResult("http://example.com/results?query=" + query, 7.5));
        return results;
    }
}

class SearchResult {
    String url;
    double relevance;

    SearchResult(String url, double relevance) {
        this.url = url;
        this.relevance = relevance;
    }
}

class ReportGenerator {
    public String generateReport(String query, List<SearchResult> results) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h1>Search Results for: ").append(query).append("</h1>");
        html.append("<div style='font-size: 14px;'>Last query: ").append(query).append("</div>");
        
        html.append("<ul style='list-style-type: none;'>");
        for (SearchResult result : results) {
            html.append("<li>")
                .append("<a href='").append(result.url).append("'>")
                .append(result.url).append("</a>")
                .append("<br>Relevance: ").append(result.relevance)
                .append("</li>");
        }
        html.append("</ul>");
        
        html.append("<script>console.log('Search query: ").append(query).append("')</script>");
        html.append("</body></html>");
        return html.toString();
    }
}