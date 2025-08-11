import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

@WebServlet("/syncCustomerData")
public class SyncDataServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String externalUrl = request.getParameter("url");
        if (externalUrl == null || externalUrl.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing URL parameter");
            return;
        }

        try {
            URL url = new URL(externalUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            // 获取响应代码
            int responseCode = connection.getResponseCode();
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuilder content = new StringBuilder();
                
                while ((inputLine = in.readLine()) != null) {
                    content.append(inputLine);
                }
                in.close();
                
                // 将外部数据直接嵌入响应
                out.println("<h2>Synced Data:</h2>");
                out.println("<pre>" + content.toString() + "</pre>");
            } else {
                out.println("<p>Failed to fetch data. Response code: " + responseCode + "</p>");
            }
            
            connection.disconnect();
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                "Error fetching external data: " + e.getMessage());
        }
    }

    // 模拟CRM系统内部接口
    @WebServlet("/internal/customerStats")
    static class InternalStatsServlet extends HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
            response.setContentType("application/json");
            PrintWriter out = response.getWriter();
            out.println("{\\"totalCustomers\\": 1500, \\"activeContracts\\": 450}");
        }
    }
}