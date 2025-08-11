package com.example.crm.controller;

import com.example.crm.model.Customer;
import com.example.crm.service.CustomerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/customers")
public class CustomerController {

    @Autowired
    private CustomerService customerService;

    @GetMapping("/add")
    public String showAddForm(Model model) {
        model.addAttribute("customer", new Customer());
        return "add-customer";
    }

    @PostMapping("/save")
    public String saveCustomer(@ModelAttribute Customer customer) {
        // 漏洞点：未对remark字段进行转义处理，直接保存到数据库
        customerService.save(customer);
        return "redirect:/customers/list";
    }

    @GetMapping("/list")
    public String listCustomers(Model model) {
        model.addAttribute("customers", customerService.getAll());
        return "customer-list";
    }

    @GetMapping("/view")
    public String viewCustomer(@RequestParam Long id, Model model) {
        Customer customer = customerService.findById(id);
        model.addAttribute("customer", customer);
        return "view-customer";
    }
}

// Customer.java
package com.example.crm.model;

import javax.persistence.*;

@Entity
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String remark; // 未进行任何转义处理

    // getters and setters
}

// view-customer.html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>View Customer</title>
</head>
<body>
    <h1>Customer Details</h1>
    <p>Name: <span th:text="${customer.name}"></span></p>
    <div th:utext="${customer.remark}"></div> <!-- 漏洞点：使用utext导致XSS -->
</body>
</html>