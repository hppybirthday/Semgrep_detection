import java.io.*;
import java.net.*;
import java.util.logging.*;

class IoTDevice {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            Logger.getLogger("IoTDevice").info("Device controller started on port 8080");
            while (true) {
                Socket socket = serverSocket.accept();
                new DeviceHandler(socket).start();
            }
        } catch (IOException e) {
            Logger.getLogger("IoTDevice").severe("Server error: " + e.getMessage());
        }
    }
}

class DeviceHandler extends Thread {
    private final Socket socket;

    public DeviceHandler(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try (ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {
            Object obj = ois.readObject();
            if (obj instanceof DeviceConfig) {
                DeviceConfig config = (DeviceConfig) obj;
                Logger.getLogger("DeviceHandler").info(
                    String.format("Updating config: IP=%s, Port=%d", config.ip, config.port)
                );
                // Simulate configuration update
                System.setProperty("device.ip", config.ip);
                System.setProperty("device.port", String.valueOf(config.port));
            } else {
                Logger.getLogger("DeviceHandler").warning("Invalid config type received");
            }
        } catch (Exception e) {
            Logger.getLogger("DeviceHandler").warning("Invalid config format: " + e.getMessage());
        }
    }
}

class DeviceConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    public String ip;
    public int port;

    public DeviceConfig(String ip, int port) {
        this.ip = ip;
        this.port = port;
    }

    // Simulate sensitive data storage
    private String[] sensorData = {"temp:37.5C", "humidity:65%"};
}