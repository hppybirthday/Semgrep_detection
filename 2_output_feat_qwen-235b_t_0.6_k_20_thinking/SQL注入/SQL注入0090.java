package com.crm.customer.controller;

import com.crm.customer.service.CustomerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/customers")
public class CustomerController {
    @Autowired
    private CustomerService customerService;

    @PostMapping("/delete")
    public String deleteCustomers(@RequestBody List<String> ids) {
        customerService.deleteCustomers(ids);
        return "{'status':'success'}";
    }
}

package com.crm.customer.service;

import com.crm.customer.dao.CustomerDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomerService {
    @Autowired
    private CustomerDAO customerDAO;

    public void deleteCustomers(List<String> ids) {
        System.out.println("Deleting customers with IDs: " + ids);
        customerDAO.deleteByIds(ids);
    }
}

package com.crm.customer.dao;

import org.beetl.sql.core.DBTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class CustomerDAO {
    @Autowired
    private DBTemplate dbTemplate;

    public void deleteByIds(List<String> ids) {
        String idList = String.join(",", ids);
        String sql = "DELETE FROM customers WHERE id IN (" + idList + ")";
        dbTemplate.update(sql);
    }
}