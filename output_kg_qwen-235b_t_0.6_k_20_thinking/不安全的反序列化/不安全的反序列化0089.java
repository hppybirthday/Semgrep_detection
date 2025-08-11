package com.crm.example;

import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/customer")
public class CustomerController {
    
    @GetMapping("/details")
    public String getCustomerDetails(@RequestParam String base64Customer) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Customer);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Customer customer = (Customer) ois.readObject();
            ois.close();
            return String.format("Customer: %s <%s>", customer.getName(), customer.getEmail());
        } catch (Exception e) {
            return "Invalid customer data";
        }
    }

    @PostMapping("/batch")
    public String processBatchCustomers(@RequestBody String batchData) {
        return java.util.Arrays.stream(batchData.split("\\u001F"))
            .map(data -> {
                try {
                    ObjectInputStream ois = new ObjectInputStream(
                        new ByteArrayInputStream(Base64.getDecoder().decode(data))
                    );
                    Customer customer = (Customer) ois.readObject();
                    ois.close();
                    return String.format("Processed: %s\
", customer.getEmail());
                } catch (Exception e) {
                    return "Error processing customer\
";
                }
            })
            .reduce("", (a, b) -> a + b);
    }
}

class Customer implements java.io.Serializable {
    private String name;
    private String email;
    
    public Customer(String name, String email) {
        this.name = name;
        this.email = email;
    }

    // Generated getters/setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}