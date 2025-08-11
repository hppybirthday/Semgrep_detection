import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.web.client.*;

@SpringBootApplication
public class MLApp {
    public static void main(String[] args) {
        SpringApplication.run(MLApp.class, args);
    }
}

@RestController
class PredictController {
    private final PredictionService service = new PredictionService();

    @PostMapping("/predict")
    public String predict(@RequestParam String dataUrl) {
        return "Prediction: " + service.makePrediction(dataUrl);
    }
}

@Service
class PredictionService {
    private final RestTemplate restTemplate = new RestTemplate();
    private final MLModel model = new DummyModel();

    public String makePrediction(String dataUrl) {
        try {
            String rawData = restTemplate.getForObject(dataUrl, String.class);
            double[] processed = preprocess(rawData);
            return String.valueOf(model.predict(processed));
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private double[] preprocess(String data) {
        return new double[]{data.hashCode() % 1000 / 100.0};
    }
}

class DummyModel {
    double predict(double[] input) {
        return input[0] * 42; // Simulated prediction logic
    }
}