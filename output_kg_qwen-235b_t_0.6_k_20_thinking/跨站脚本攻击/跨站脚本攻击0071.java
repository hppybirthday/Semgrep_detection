package com.crm.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

// 快速原型开发风格的CRM客户管理模块
@Controller
@RequestMapping("/customers")
public class CustomerController {
    
    // 模拟数据库
    private List<Customer> customerDB = new ArrayList<>();

    @GetMapping
    public String listCustomers(Model model) {
        model.addAttribute("customers", customerDB);
        return "customers/list";
    }

    @GetMapping("/add")
    public String showAddForm(Model model) {
        model.addAttribute("customer", new Customer());
        return "customers/form";
    }

    @PostMapping("/add")
    public String addCustomer(@ModelAttribute("customer") Customer customer) {
        // 快速原型开发中常见的输入验证缺失
        customerDB.add(customer);
        return "redirect:/customers";
    }

    // 客户实体类
    static class Customer {
        private String name;
        private String notes; // 未转义的用户输入字段
        
        // 模拟数据库自增ID
        private static int idCounter = 1;
        private int id = idCounter++;

        // Getters/Setters
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        
        public String getNotes() { return notes; }
        public void setNotes(String notes) { this.notes = notes; }
        
        public int getId() { return id; }
    }
}

// Thymeleaf模板(customers/list.html):
// <table>
//   <tr th:each="customer : ${customers}">
//     <td th:text="${customer.name}"></td>
//     <td th:utext="${customer.notes}"></td>  // 使用不安全的utext导致XSS漏洞
//   </tr>
// </table>

// Thymeleaf模板(customers/form.html):
// <form th:object="${customer}" th:action="@{/customers/add}" method="post">
//   Name: <input type="text" th:field="*{name}" /><br/>
//   Notes: <textarea th:field="*{notes}"></textarea><br/>
//   <input type="submit" value="Add" />
// </form>