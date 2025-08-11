import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

@RestController
@RequestMapping("/api")
public class FinancialController {
    private final CurrencyService currencyService;

    public FinancialController(CurrencyService currencyService) {
        this.currencyService = currencyService;
    }

    @GetMapping("/exchange-rate")
    public String getExchangeRate(@RequestParam String currencyUrl) {
        try {
            return currencyService.fetchExchangeRate(currencyUrl);
        } catch (IOException e) {
            return "Error fetching exchange rate: " + e.getMessage();
        }
    }
}

interface CurrencyService {
    String fetchExchangeRate(String currencyUrl) throws IOException;
}

@Component
class ExternalCurrencyService implements CurrencyService {
    @Override
    public String fetchExchangeRate(String currencyUrl) throws IOException {
        URL url = new URL(currencyUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        }
        
        return response.toString();
    }
}

@Configuration
class AppConfig {
    @Bean
    public CurrencyService currencyService() {
        return new ExternalCurrencyService();
    }
}