package com.crm.customer.controller;

import com.crm.customer.service.CustomerService;
import com.crm.customer.dto.DeleteRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/customer")
public class CustomerController {
    @Autowired
    private CustomerService customerService;

    @PostMapping("/delete")
    public String deleteCustomers(@RequestBody DeleteRequest request) {
        if (request.getIds().isEmpty()) {
            return "No IDs provided";
        }
        
        // 检查ID格式是否为数字列表
        if (!request.getIds().matches("^[0-9,]*$")) {
            return "Invalid ID format";
        }
        
        // 调用服务层处理删除
        try {
            customerService.deleteCustomers(request.getIds());
            return "Delete successful";
        } catch (Exception e) {
            return "Delete failed: " + e.getMessage();
        }
    }
}

package com.crm.customer.service;

import com.crm.customer.dao.CustomerDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CustomerService {
    @Autowired
    private CustomerDAO customerDAO;

    public void deleteCustomers(String ids) {
        // 模拟业务逻辑处理
        if (ids.contains("'")) {
            ids = ids.replace("'", "");
        }
        
        // 错误地传递原始ID字符串
        customerDAO.deleteCustomers(ids);
    }
}

package com.crm.customer.dao;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface CustomerDAO {
    // 存在SQL注入风险的错误实现
    @Delete({"<script>",
        "DELETE FROM customers WHERE id IN (${ids})",
        "</script>"})
    void deleteCustomers(String ids);
}

package com.crm.customer.dto;

import lombok.Data;

@Data
public class DeleteRequest {
    private String ids;
}

// MyBatis配置类
package com.crm.customer.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@MapperScan("com.crm.customer.dao")
public class MyBatisConfig {}

// 实体类
package com.crm.customer.model;

import lombok.Data;

@Data
public class Customer {
    private Long id;
    private String name;
    private String email;
}

// Spring Boot主类
package com.crm.customer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CustomerApplication {
    public static void main(String[] args) {
        SpringApplication.run(CustomerApplication.class, args);
    }
}