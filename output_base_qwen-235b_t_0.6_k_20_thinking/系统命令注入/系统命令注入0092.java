import java.io.*;
import java.util.*;
import java.util.stream.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/customers")
public class CustomerController {
    private List<Customer> customers = new ArrayList<>();

    @PostMapping("/add")
    public String addCustomer(@RequestParam String name, @RequestParam String email) {
        customers.add(new Customer(name, email));
        return "Customer added";
    }

    @GetMapping("/export")
    public String exportCustomers(@RequestParam String fileName) {
        try {
            FileWriter writer = new FileWriter("/tmp/" + fileName + ".csv");
            writer.write(customers.stream()
                .map(c -> c.getName() + "," + c.getEmail())
                .collect(Collectors.joining("\
")));
            writer.close();

            // Vulnerable command execution
            Process process = Runtime.getRuntime().exec(
                new String[]{"/bin/sh", "-c", "zip -r /tmp/" + fileName + " /tmp/" + fileName + ".csv"}
            );
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
            return "Exported to /tmp/" + fileName + ".zip";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    static class Customer {
        private String name;
        private String email;

        Customer(String name, String email) {
            this.name = name;
            this.email = email;
        }

        String getName() { return name; }
        String getEmail() { return email; }
    }
}