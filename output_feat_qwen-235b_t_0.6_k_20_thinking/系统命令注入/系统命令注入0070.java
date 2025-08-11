import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;

@WebFilter("/device/*")
public class DeviceCommandFilter implements Filter {
    
    public void init(FilterConfig fConfig) throws ServletException {
        // 初始化设备配置
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String action = httpRequest.getParameter("action");
        String deviceParam = httpRequest.getParameter("device");
        
        if("collect_data".equals(action) && deviceParam != null) {
            // 模拟IoT设备数据采集命令构造
            String command = "collect-device-data --device=" + deviceParam;
            
            // 存在漏洞的命令执行
            try {
                Process process = Runtime.getRuntime().exec(command);
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
                process.waitFor();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        chain.doFilter(request, response);
    }

    public void destroy() {
        // 清理资源
    }

    // 模拟IoT设备控制类
    static class IoTDeviceController {
        public String executeSystemCommand(String command) {
            try {
                Process process = Runtime.getRuntime().exec(command);
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
                return output.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
}