package com.crm.customer.controller;

import com.crm.customer.service.CustomerService;
import com.crm.customer.dto.CustomerQueryDTO;
import com.crm.common.utils.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/customer")
public class CustomerController {
    @Autowired
    private CustomerService customerService;

    @GetMapping("/list")
    public Result<List<Customer>> getCustomers(CustomerQueryDTO queryDTO) {
        // 处理分页查询请求
        List<Customer> customers = customerService.getCustomers(queryDTO);
        return Result.success(customers);
    }
}

// Service层
package com.crm.customer.service;

import com.crm.customer.dao.CustomerDAO;
import com.crm.customer.dto.CustomerQueryDTO;
import com.crm.customer.model.Customer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomerService {
    @Autowired
    private CustomerDAO customerDAO;

    public List<Customer> getCustomers(CustomerQueryDTO queryDTO) {
        // 校验参数有效性
        if (queryDTO.getPageNum() <= 0) {
            queryDTO.setPageNum(1);
        }
        if (queryDTO.getPageSize() <= 0 || queryDTO.getPageSize() > 100) {
            queryDTO.setPageSize(20);
        }

        // 处理排序参数
        String orderField = "create_time";
        String orderDirection = "desc";
        if (queryDTO.getOrderField() != null && !queryDTO.getOrderField().isEmpty()) {
            orderField = queryDTO.getOrderField().trim().toLowerCase();
        }
        if (queryDTO.getOrderDirection() != null && !queryDTO.getOrderDirection().isEmpty()) {
            orderDirection = queryDTO.getOrderDirection().trim().toLowerCase();
        }

        // 查询数据
        return customerDAO.getCustomers(orderField, orderDirection);
    }
}

// DAO层
package com.crm.customer.dao;

import com.crm.customer.model.Customer;
import org.beetl.sql.annotation.SQL;
import org.beetl.sql.core.BaseDAO;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CustomerDAO extends BaseDAO {
    @SQL("SELECT * FROM customers ORDER BY ${orderField} ${orderDirection}")
    List<Customer> getCustomers(String orderField, String orderDirection);
}

// DTO
package com.crm.customer.dto;

import lombok.Data;

@Data
public class CustomerQueryDTO {
    private Integer pageNum;
    private Integer pageSize;
    private String orderField;
    private String orderDirection;
}

// Model
package com.crm.customer.model;

import lombok.Data;

@Data
public class Customer {
    private Long id;
    private String name;
    private String email;
    private String phone;
    private String createTime;
}