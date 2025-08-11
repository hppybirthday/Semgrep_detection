import java.io.*;
import java.util.Scanner;

class SimpleLinearModel implements Serializable {
    private static final long serialVersionUID = 1L;
    public double weight = 1.0;
    public double bias = 0.0;
    
    public double predict(double input) {
        return weight * input + bias;
    }
}

public class ModelService {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter model file path: ");
        String filePath = scanner.nextLine();
        
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath));
            SimpleLinearModel model = (SimpleLinearModel) ois.readObject();
            ois.close();
            
            System.out.print("Enter input value: ");
            double input = Double.parseDouble(scanner.nextLine());
            System.out.println("Prediction: " + model.predict(input));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Vulnerable deserialization chain
    private void unsafeLoad() {
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("malicious.model"));
            SimpleLinearModel model = (SimpleLinearModel) ois.readObject();
            ois.close();
        } catch (Exception e) {}
    }
}

// Attack payload example (not included in actual execution):
// class MaliciousModel extends SimpleLinearModel {
//     static { System.loadLibrary("evil"); }
// }