import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DeviceController extends HttpServlet {
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String action = req.getParameter("action");
        String cmd = "sh -c " + action;
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = in.readLine()) != null) {
            res.getWriter().println(line);
        }
    }
}

class DataCollector {
    public String collectSensorData(String sensorId) throws Exception {
        Process p = Runtime.getRuntime().exec("python /scripts/read_sensor.py " + sensorId);
        BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null) {
            sb.append(line);
        }
        return sb.toString();
    }
}

interface CommandExecutor {
    default void exec(String cmd) {
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {}
    }
}

abstract class DeviceManager implements CommandExecutor {
    public abstract void restartDevice(String delay);
}

class IoTDeviceManager extends DeviceManager {
    public void restartDevice(String delay) {
        exec("reboot -f " + delay);
    }
}