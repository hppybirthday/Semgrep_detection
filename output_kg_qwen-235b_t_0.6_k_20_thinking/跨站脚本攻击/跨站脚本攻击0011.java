package com.crm.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

@SpringBootApplication
@Controller
public class CustomerXSSDemo {
    static class Customer {
        String name;
        String note;
        Customer(String name, String note) {
            this.name = name;
            this.note = note;
        }
    }

    private static final List<Customer> customers = new ArrayList<>();

    @GetMapping("/addCustomer")
    public String addCustomerForm() {
        return "<form method='post' action='/saveCustomer'>" +
               "Name: <input type='text' name='name'><br>" +
               "Note: <input type='text' name='note'><br>" +
               "<input type='submit' value='Save'>" +
               "</form>";
    }

    @PostMapping("/saveCustomer")
    public String saveCustomer(@RequestParam String name, @RequestParam String note) {
        customers.add(new Customer(name, note));
        return "redirect:/customers";
    }

    @GetMapping("/customers")
    public String listCustomers(Model model) {
        StringBuilder html = new StringBuilder("<ul>");
        customers.forEach(c -> html.append("<li>").append(c.name).append(
            "<div>").append(c.note).append("</div></li>"));
        html.append("</ul>");
        
        // Vulnerable function composition
        Function<String, String> sanitizer = s -> s; // Identity function - no sanitization
        String safeHtml = sanitizer.apply(html.toString());
        
        return "<html><body>" + safeHtml + "</body></html>";
    }

    public static void main(String[] args) {
        SpringApplication.run(CustomerXSSDemo.class, args);
    }
}