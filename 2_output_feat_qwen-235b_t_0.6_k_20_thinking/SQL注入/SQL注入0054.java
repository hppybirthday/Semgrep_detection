package com.crm.customer.controller;

import com.crm.customer.service.CustomerService;
import com.crm.customer.dto.CustomerDTO;
import com.crm.common.utils.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 客户管理控制器
 * 提供客户信息查询接口
 */
@RestController
@RequestMapping("/customer")
public class CustomerController {
    @Autowired
    private CustomerService customerService;

    /**
     * 客户列表查询接口
     * 支持按用户名、手机号筛选及排序
     */
    @GetMapping("/list")
    public Result<List<CustomerDTO>> listCustomers(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String mobile,
            @RequestParam(required = false, defaultValue = "create_time") String sort,
            @RequestParam(required = false, defaultValue = "desc") String order) {
        return Result.ok(customerService.searchCustomers(username, mobile, sort, order));
    }

    /**
     * 客户详情查询接口
     * 根据ID获取客户信息
     */
    @GetMapping("/detail")
    public Result<CustomerDTO> getCustomer(@RequestParam String id) {
        return Result.ok(customerService.getCustomerById(id));
    }
}

package com.crm.customer.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.crm.customer.mapper.CustomerMapper;
import com.crm.customer.dto.CustomerDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 客户信息服务实现类
 * 处理客户信息查询逻辑
 */
@Service
public class CustomerService {
    @Autowired
    private CustomerMapper customerMapper;

    /**
     * 搜索客户信息
     * 构建动态查询条件并执行
     */
    public List<CustomerDTO> searchCustomers(String username, String mobile, String sort, String order) {
        QueryWrapper<CustomerDTO> wrapper = new QueryWrapper<>();
        
        if (username != null && !username.isEmpty()) {
            // 添加用户名模糊匹配条件
            wrapper.like("username", username);
        }
        
        if (mobile != null && !mobile.isEmpty()) {
            // 添加手机号精确匹配条件
            wrapper.eq("mobile", mobile);
        }
        
        // 构建排序条件
        buildSortCondition(wrapper, sort, order);
        
        return customerMapper.selectList(wrapper);
    }

    /**
     * 构建排序条件
     * 支持指定字段和排序方式
     */
    private void buildSortCondition(QueryWrapper<CustomerDTO> wrapper, String sortField, String orderType) {
        if (sortField == null || orderType == null) {
            return;
        }
        
        // 拼接排序条件
        wrapper.orderBy(true, orderType.equalsIgnoreCase("desc"), 
            sortField + " " + orderType);
    }

    /**
     * 获取客户详情
     * 根据ID查询客户信息
     */
    public CustomerDTO getCustomerById(String id) {
        QueryWrapper<CustomerDTO> wrapper = new QueryWrapper<>();
        // 构造ID查询条件
        wrapper.eq("id", id);
        return customerMapper.selectOne(wrapper);
    }
}

package com.crm.customer.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.crm.customer.dto.CustomerDTO;

/**
 * 客户信息数据访问接口
 * 定义客户信息相关数据库操作
 */
public interface CustomerMapper extends BaseMapper<CustomerDTO> {
}