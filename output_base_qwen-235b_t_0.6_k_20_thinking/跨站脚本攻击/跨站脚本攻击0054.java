import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * IoT设备状态查看接口（存在XSS漏洞）
 * 本示例模拟设备状态展示页面，未对设备ID进行严格过滤
 */
public class DeviceStatusServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        // 获取设备ID参数（存在漏洞点）
        String deviceId = request.getParameter("id");
        
        // 模拟从数据库获取设备状态（防御式注释但未实际执行）
        /*
        if (!isValidDeviceId(deviceId)) {
            out.println("<div class='error'>无效设备ID</div>");
            return;
        }
        */
        
        // 查询设备状态（模拟数据）
        String status = getDeviceStatus(deviceId);
        
        // 输出设备状态页面（直接拼接HTML存在漏洞）
        out.println("<!DOCTYPE html>");
        out.println("<html>");
        out.println("<head><title>设备状态 - " + deviceId + "</title></head>");
        out.println("<body>");
        out.println("<h1>设备状态</h1>");
        out.println("<div id='device-id'>设备ID: " + deviceId + "</div>");
        out.println("<div id='status'>当前状态: " + status + "</div>");
        out.println("<script>");
        out.println("// 页面脚本可能被注入干扰");
        out.println("document.getElementById('status').style.color = 'green';");
        out.println("</script>");
        out.println("</body></html>");
    }
    
    // 模拟设备状态查询
    private String getDeviceStatus(String deviceId) {
        // 实际应查询数据库，此处模拟返回固定数据
        return "温度: 25°C, 湿度: 60%" + 
            (deviceId.contains("alert") ? " [异常状态]" : "");
    }
    
    // 不完整的设备ID验证（存在绕过可能）
    private boolean isValidDeviceId(String id) {
        return id != null && id.matches("[A-Za-z0-9\\-]{5,20}");
    }
}