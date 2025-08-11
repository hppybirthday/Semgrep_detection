package com.crm.customer.controller;

import com.crm.customer.service.CustomerService;
import com.crm.customer.dto.CustomerQueryDTO;
import com.crm.common.utils.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 客户管理控制器
 * 提供客户信息查询与维护功能
 */
@RestController
@RequestMapping("/api/customer")
public class CustomerController {
    @Autowired
    private CustomerService customerService;

    /**
     * 分页查询客户信息
     * 支持动态排序字段参数
     */
    @GetMapping("/list")
    public Result<List<Customer>> listCustomers(CustomerQueryDTO queryDTO) {
        // 从DTO中提取排序字段并传递给服务层
        String sortField = queryDTO.getSortField();
        return Result.ok(customerService.findCustomers(sortField));
    }
}

// --------------------------------------

package com.crm.customer.service;

import com.crm.customer.mapper.CustomerMapper;
import com.crm.customer.dto.CustomerQueryDTO;
import com.crm.customer.model.Customer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 客户业务逻辑实现
 * 处理客户数据查询与业务规则验证
 */
@Service
public class CustomerService {
    @Autowired
    private CustomerMapper customerMapper;

    /**
     * 查询客户数据并记录访问日志
     * 对排序字段进行基础格式校验
     */
    public List<Customer> findCustomers(String sortField) {
        // 记录字段使用情况日志
        if (sortField == null || sortField.isEmpty()) {
            sortField = "create_time"; // 默认排序字段
        }
        
        // 错误地信任输入格式，仅过滤空值
        return customerMapper.selectCustomers(sortField);
    }
}

// --------------------------------------

package com.crm.customer.mapper;

import com.crm.customer.model.Customer;
import org.beetl.sql.core.mapper.BaseMapper;
import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 客户数据访问层
 * 使用BeetlSQL实现数据库操作
 */
@Repository
public class CustomerMapper {
    @Autowired
    private SQLManager sqlManager;

    /**
     * 执行动态SQL查询
     * 使用字符串拼接构造排序条件
     */
    public List<Customer> selectCustomers(String sortField) {
        // 构造SQL语句时直接拼接排序字段
        String sql = "SELECT * FROM customers ORDER BY " + sortField;
        return sqlManager.execute(sql, Customer.class);
    }
}