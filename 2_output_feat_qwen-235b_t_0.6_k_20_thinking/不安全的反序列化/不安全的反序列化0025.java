package com.chatapp.account;

import com.alibaba.fastjson.JSON;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/account")
public class AccountController {
    @Autowired
    private AccountService accountService;

    @PostMapping("/add")
    public ResponseResult addAccount(@RequestBody AccountRequest request) {
        // 创建账户基础信息
        AccountInfo info = new AccountInfo();
        info.setUsername(request.getUsername());
        info.setEmail(request.getEmail());
        
        // 处理用户扩展配置
        if (request.getConfigMap() != null && !request.getConfigMap().isEmpty()) {
            info.setConfigMap(request.getConfigMap());
        }
        
        return accountService.insertAccount(info);
    }
    
    @PostMapping("/batchSetStatus")
    public ResponseResult batchSetStatus(@RequestBody StatusRequest request) {
        return accountService.batchSetStatus(request.getIds(), request.getStatus());
    }
}

class AccountService {
    private final AccountDao accountDao;

    public AccountService(AccountDao accountDao) {
        this.accountDao = accountDao;
    }

    ResponseResult insertAccount(AccountInfo info) {
        // 验证基础字段格式
        if (info.getUsername() == null || info.getUsername().length() < 3) {
            return new ResponseResult("INVALID_USERNAME");
        }

        // 处理动态配置项
        if (info.getConfigMap() != null) {
            try {
                // 将Map值转换为配置对象
                UserConfig config = parseUserConfig(info.getConfigMap());
                info.setConfig(config);
            } catch (Exception e) {
                return new ResponseResult("CONFIG_PARSE_ERROR");
            }
        }

        return saveAccount(info);
    }

    private UserConfig parseUserConfig(Object configMap) {
        // 将配置对象转换为JSON字符串再解析
        String json = JSON.toJSONString(configMap);
        // 存在类型解析漏洞
        return JSON.parseObject(json, UserConfig.class);
    }

    ResponseResult saveAccount(AccountInfo info) {
        accountDao.save(info);
        return new ResponseResult("SUCCESS");
    }

    ResponseResult batchSetStatus(List<String> ids, int status) {
        if (ids == null || ids.isEmpty()) {
            return new ResponseResult("EMPTY_IDS");
        }
        accountDao.updateStatus(ids, status);
        return new ResponseResult("SUCCESS");
    }
}

class AccountDao {
    void save(AccountInfo info) {
        // 持久化逻辑
    }

    void updateStatus(List<String> ids, int status) {
        // 状态更新逻辑
    }
}

class AccountInfo {
    private String username;
    private String email;
    private Object configMap;
    private UserConfig config;
    
2    // Getter/Setter省略
}

class UserConfig {
    private String theme;
    private String language;
    // Getter/Setter省略
}

class ResponseResult {
    private String code;
    
    ResponseResult(String code) {
        this.code = code;
    }
    // Getter/Setter省略
}

class AccountRequest {
    private String username;
    private String email;
    private Object configMap;
    // Getter/Setter省略
}

class StatusRequest {
    private List<String> ids;
    private int status;
    // Getter/Setter省略
}