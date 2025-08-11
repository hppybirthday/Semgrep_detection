package com.crm.demo.controller;

import com.crm.demo.service.CustomerService;
import com.crm.demo.model.Customer;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/customers")
public class CustomerController {
    @Autowired
    private CustomerService customerService;

    @GetMapping
    public PageInfo<Customer> getCustomers(@RequestParam int pageNum, 
                                            @RequestParam int pageSize,
                                            @RequestParam(required = false) String orderBy) {
        PageHelper.startPage(pageNum, pageSize);
        if (orderBy != null && !orderBy.isEmpty()) {
            PageHelper.orderBy(orderBy); // 漏洞点：直接拼接排序参数
        }
        List<Customer> customers = customerService.getAllCustomers();
        return new PageInfo<>(customers);
    }
}

package com.crm.demo.service;

import com.crm.demo.mapper.CustomerMapper;
import com.crm.demo.model.Customer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomerService {
    @Autowired
    private CustomerMapper customerMapper;

    public List<Customer> getAllCustomers() {
        return customerMapper.selectAll();
    }
}

package com.crm.demo.mapper;

import com.crm.demo.model.Customer;
import org.apache.ibatis.annotations.Select;
import java.util.List;

public interface CustomerMapper {
    @Select({"<script>",
      "SELECT * FROM customers",
      "<if test='orderBy != null'>ORDER BY ${orderBy}</if>", // MyBatis动态SQL拼接
      "</script>"})
    List<Customer> selectAll();
}

// MyBatis配置文件（片段）
// <plugins>
//     <plugin interceptor="com.github.pagehelper.PageInterceptor"/>
// </plugins>