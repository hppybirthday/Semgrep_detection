package com.crm.example;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// Controller层
@RestController
@RequestMapping("/clients")
class ClientController {
    @Autowired
    private ClientService clientService;

    @GetMapping
    public List<Client> searchClients(@RequestParam String condition) {
        return clientService.findClients(condition);
    }
}

// Service层
@Service
class ClientService extends ServiceImpl<ClientMapper, Client> {
    public List<Client> findClients(String condition) {
        // 漏洞点：直接拼接用户输入到查询条件
        QueryWrapper<Client> wrapper = new QueryWrapper<>();
        wrapper.apply(condition); // 危险用法
        return query().list(wrapper);
    }
}

// Mapper接口
interface ClientMapper extends BaseMapper<Client> {}

// 实体类
class Client {
    private Long id;
    private String clientName;
    private String contactEmail;
    // getters/setters
}

/*
* 漏洞示例说明：
* 1. 攻击者可提交："1=1 UNION SELECT * FROM users--"
* 2. 导致查询变成：SELECT * FROM clients WHERE (1=1 UNION SELECT * FROM users)
* 3. 攻击者可窃取敏感表数据或执行DELETE操作
* 4. MyBatis的apply()方法直接拼接字符串，未使用参数绑定
* 5. 违反OWASP A1:2017 SQL注入防护原则
*/