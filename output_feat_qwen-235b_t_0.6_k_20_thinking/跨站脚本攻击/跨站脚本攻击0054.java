import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;
import org.json.JSONObject;

/**
 * IoT设备控制面板
 * 模拟设备状态查询接口
 * @XssCleanIgnore 注解错误导致跳过XSS过滤
 */
@XssCleanIgnore
public class DeviceControlServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        String deviceId = request.getParameter("device_id");
        String errorMsg = request.getParameter("error_msg"); // 漏洞点：直接获取未验证的参数
        
        try {
            // 模拟设备数据获取
            DeviceData data = fetchDeviceData(deviceId);
            
            // 生成HTML响应
            out.println("<html><head><title>设备控制面板</title>");
            out.println("<script>function updateStatus(){");
            out.println("  document.getElementById('status').innerHTML = '" + data.getStatus() + "';"); // 漏洞点：直接拼接脚本
            out.println("}</script></head><body>");
            
            // 错误消息显示模块
            if(errorMsg != null && !errorMsg.isEmpty()) {
                out.println("<div class='error'>" + errorMsg + "</div>"); // 漏洞点：直接输出HTML
            }
            
            // 设备控制表单
            out.println("<form action='/control'>
                <input type='hidden' name='device_id' value='" + deviceId + "'>
                <button type='submit'>重启设备</button>
            </form>");
            
            // 设备状态显示
            out.println("<div id='status'>加载中...</div>");
            out.println("<script>setTimeout(updateStatus, 1000);</script>");
            
            // 设备日志下载链接
            out.println("<a href='javascript:downloadLog(\\"" + deviceId + "\\")'>下载日志</a>"); // 漏洞点：注入到JS上下文
            
        } finally {
            out.close();
        }
    }
    
    // 模拟设备数据查询
    private DeviceData fetchDeviceData(String deviceId) {
        // 实际应包含数据库查询和输入验证
        return new DeviceData("<script>alert(document.cookie)</script>"); // 测试用恶意数据
    }
    
    // 设备数据模型
    class DeviceData {
        private String status;
        public DeviceData(String status) {
            this.status = status;
        }
        public String getStatus() {
            return status;
        }
    }
}

// 自定义注解模拟安全检查绕过
@interface XssCleanIgnore {}
