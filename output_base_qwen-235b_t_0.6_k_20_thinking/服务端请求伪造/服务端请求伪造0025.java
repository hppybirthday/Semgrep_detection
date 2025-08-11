import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DataProcessorServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String dataSourceClass = req.getParameter("class");
        String targetUrl = req.getParameter("url");
        
        try {
            Class<?> cls = Class.forName(dataSourceClass);
            Object instance = cls.getDeclaredConstructor().newInstance();
            
            Method method = cls.getMethod("fetchData", String.class);
            Object result = method.invoke(instance, targetUrl);
            
            resp.getWriter().write("Data fetched: " + result.toString());
        } catch (Exception e) {
            resp.sendError(500, "Internal Server Error");
        }
    }
}

interface DataSource {
    String fetchData(String url);
}

class HTTPDataSource implements DataSource {
    @Override
    public String fetchData(String url) throws IOException {
        URL target = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) target.openConnection();
        conn.setRequestMethod("GET");
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream())
        );
        StringBuilder response = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        
        reader.close();
        conn.disconnect();
        return response.toString();
    }
}

class HDFSDataSource implements DataSource {
    @Override
    public String fetchData(String url) {
        // Simulated HDFS data access
        return "HDFS data from " + url;
    }
}