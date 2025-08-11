import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/sensorData")
public class SensorDataCollector extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Pattern IP_PATTERN = Pattern.compile("^\\\\d{1,3}\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}$");

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String ipAddress = request.getParameter("ip");
        if (ipAddress == null || !IP_PATTERN.matcher(ipAddress).find()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid IP address");
            return;
        }

        try {
            ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", ipAddress);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder output = new StringBuilder();
            
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            response.getWriter().println("Exit code: " + exitCode);
            response.getWriter().println("Output: " + output.toString());
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                "Error executing command: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // 模拟设备控制接口
    private void controlIoTDevice(String command) {
        try {
            Runtime.getRuntime().exec("/usr/bin/python /scripts/device_ctl.py " + command);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}