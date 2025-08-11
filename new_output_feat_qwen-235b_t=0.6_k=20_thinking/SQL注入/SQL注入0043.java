package com.crm.customer.controller;

import com.crm.customer.dto.CustomerQueryDTO;
import com.crm.customer.service.CustomerService;
import com.crm.common.api.CommonPage;
import com.crm.common.api.CommonResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 客户管理控制器
 * @author CRM Team
 */
@RestController
@Tag(name = "CustomerController", description = "客户信息管理")
@RequestMapping("/api/v1/customers")
public class CustomerController {
    @Autowired
    private CustomerService customerService;

    @Operation(summary = "分页查询客户")
    @GetMapping("/list")
    public CommonResult<CommonPage<List<CustomerQueryDTO>>> list(
            @RequestParam(value = "pageNum", defaultValue = "1") int pageNum,
            @RequestParam(value = "pageSize", defaultValue = "10") int pageSize,
            @RequestParam(value = "sortField", required = false) String sortField) {
        
        // 漏洞点：未验证sortField合法性直接传递给服务层
        List<CustomerQueryDTO> customers = customerService.getCustomers(pageNum, pageSize, sortField);
        CommonPage<List<CustomerQueryDTO>> page = new CommonPage<>();
        page.setList(customers);
        page.setPageNum(pageNum);
        page.setPageSize(pageSize);
        return CommonResult.success(page);
    }

    @Operation(summary = "批量删除客户")
    @PostMapping("/delete")
    public CommonResult<Void> deleteCustomers(@RequestParam("ids") List<Long> ids) {
        customerService.deleteCustomers(ids);
        return CommonResult.success(null);
    }
}

// Service层
package com.crm.customer.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.crm.customer.dto.CustomerQueryDTO;
import com.crm.customer.mapper.CustomerMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 客户服务实现
 */
@Service
public class CustomerService {
    @Autowired
    private CustomerMapper customerMapper;

    public List<CustomerQueryDTO> getCustomers(int pageNum, int pageSize, String sortField) {
        Page<CustomerQueryDTO> page = new Page<>(pageNum, pageSize);
        
        // 漏洞点：直接拼接排序字段
        // 误以为MyBatis Plus会自动处理字段名
        page.orderBy(true, sortField != null && !sortField.isEmpty(), sortField);
        
        QueryWrapper<CustomerQueryDTO> queryWrapper = new QueryWrapper<>();
        // 本意是查询所有客户，但分页条件被污染
        return customerMapper.selectPage(page, queryWrapper).getRecords();
    }

    public void deleteCustomers(List<Long> ids) {
        // 安全写法：使用MyBatis Plus内置方法
        customerMapper.deleteBatchIds(ids);
    }
}

// Mapper层
package com.crm.customer.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.crm.customer.dto.CustomerQueryDTO;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface CustomerMapper extends BaseMapper<CustomerQueryDTO> {
    // 使用MyBatis Plus分页插件
}