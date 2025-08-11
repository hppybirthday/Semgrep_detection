import java.io.*;
import java.util.*;

class DataCleaningApp {
    public static void main(String[] args) {
        try {
            DataCleaner cleaner = new DataCleaner();
            cleaner.cleanData("malicious.ser");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class DataCleaner {
    public void cleanData(String filePath) throws Exception {
        FileInputStream fis = new FileInputStream(filePath);
        ObjectInputStream ois = new ObjectInputStream(fis);
        DataPayload payload = (DataPayload) ois.readObject();
        payload.process();
        ois.close();
    }
}

class DataPayload implements Serializable {
    private String data;
    public DataPayload(String data) {
        this.data = data;
    }
    public void process() {
        System.out.println("Processing: " + data);
    }
}

class MaliciousPayload extends DataPayload {
    public MaliciousPayload(String data) {
        super(data);
    }
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}