package com.example.bigdata.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.bigdata.service.ClientService;
import com.example.bigdata.model.Client;
import com.github.pagehelper.PageHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/clients")
public class ClientController {
    @Autowired
    private ClientService clientService;

    @GetMapping
    public List<Client> getClients(@RequestParam("sortField") String sortField) {
        // 漏洞点：直接拼接用户输入到排序参数中
        PageHelper.orderBy(sortField);
        return clientService.list(new QueryWrapper<Client>().eq("status", 1));
    }
}

// Mapper层（自动生成）
package com.example.bigdata.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.bigdata.model.Client;
import java.util.List;

public interface ClientMapper extends BaseMapper<Client> {
    List<Client> selectClientsWithSort(@Param("sortField") String sortField);
}

// Service层
package com.example.bigdata.service;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.bigdata.mapper.ClientMapper;
import com.example.bigdata.model.Client;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ClientServiceImpl extends ServiceImpl<ClientMapper, Client> implements ClientService {
    @Override
    public List<Client> listClients(String sortField) {
        return baseMapper.selectClientsWithSort(sortField);
    }
}

// MyBatis XML映射
<!-- ClientMapper.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.bigdata.mapper.ClientMapper">
    <select id="selectClientsWithSort" resultType="com.example.bigdata.model.Client">
        SELECT * FROM clients
        <where>
            status = 1
        </where>
        ORDER BY ${sortField}  <!-- 漏洞点：使用$符号导致SQL注入 -->
    </select>
</mapper>

// 实体类
package com.example.bigdata.model;

import lombok.Data;

@Data
public class Client {
    private Long id;
    private String name;
    private Integer status;
}