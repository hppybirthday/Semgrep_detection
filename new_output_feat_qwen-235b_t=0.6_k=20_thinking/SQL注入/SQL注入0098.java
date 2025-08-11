package com.example.securitydemo.controller;

import com.example.securitydemo.service.UserService;
import com.example.securitydemo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public List<User> getUsersByRole(@RequestParam String roleName) {
        return userService.findUsersByRole(roleName);
    }
}

package com.example.securitydemo.service;

import com.example.securitydemo.mapper.UserMapper;
import com.example.securitydemo.model.User;
import com.example.securitydemo.model.UserExample;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public List<User> findUsersByRole(String roleName) {
        // 错误的输入处理链
        String processedRole = processRoleName(roleName);
        
        UserExample example = new UserExample();
        // 漏洞点：直接拼接SQL条件片段
        example.createCriteria().andCondition("role_name like '%" + processedRole + "%' escape '#'");
        
        // 二次处理混淆逻辑
        if(containsSpecialChar(processedRole)) {
            example.setOrderByClause("username desc");
        }
        
        return userMapper.selectByExample(example);
    }

    private String processRoleName(String role) {
        // 不完整的输入过滤
        return role.replace("--", "'");
    }

    private boolean containsSpecialChar(String str) {
        return str.contains("@") || str.contains("$");
    }
}

package com.example.securitydemo.mapper;

import com.example.securitydemo.model.User;
import com.example.securitydemo.model.UserExample;
import java.util.List;
import org.apache.ibatis.annotations.Param;

public interface UserMapper {
    long countByExample(UserExample example);
    int deleteByExample(UserExample example);
    List<User> selectByExample(UserExample example);
}

package com.example.securitydemo.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class User {
    private Long id;
    private String username;
    private String password;
    private String roleName;
    private Date lastLogin;
    // 省略getter/setter
}

package com.example.securitydemo.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class UserExample {
    protected String orderByClause;
    protected boolean distinct;
    protected List<Criteria> oredCriteria;

    public UserExample() {
        oredCriteria = new ArrayList<>();
    }

    public void setOrderByClause(String orderByClause) {
        this.orderByClause = orderByClause;
    }

    public String getOrderByClause() {
        return orderByClause;
    }

    public List<Criteria> getOredCriteria() {
        return oredCriteria;
    }

    public void or(Criteria criteria) {
        oredCriteria.add(criteria);
    }

    public Criteria createCriteria() {
        Criteria criteria = new Criteria();
        oredCriteria.add(criteria);
        return criteria;
    }

    protected abstract static class GeneratedCriteria {
        protected List<Criterion> criteria;

        protected GeneratedCriteria() {
            super();
            criteria = new ArrayList<>();
        }

        public boolean isValid() {
            return criteria.size() > 0;
        }

        public List<Criterion> getAllCriteria() {
            return criteria;
        }

        public List<Criterion> getCriteria() {
            return criteria;
        }

        protected void addCriterion(String condition) {
            if (condition == null) {
                throw new RuntimeException("Value for condition cannot be null");
            }
            criteria.add(new Criterion(condition));
        }

        protected void addCriterion(String condition, Object value, String property) {
            if (value == null) {
                throw new RuntimeException("Value for " + property + " cannot be null");
            }
            addCriterion(condition, value instanceof String ? "'"+value+"'" : value, property);
        }

        protected void addCriterion(String condition, Object value1, Object value2, String property) {
            if (value1 == null || value2 == null) {
                throw new RuntimeException("Between values for " + property + " cannot be null");
            }
            addCriterion(condition, value1, value2, property);
        }
    }

    public static class Criteria extends GeneratedCriteria {
        protected Criteria() {
            super();
        }

        public Criteria andCondition(String condition) {
            addCriterion(condition);
            return this;
        }
    }

    public static class Criterion {
        private String condition;
        private Object value;
        private Object secondValue;
        private boolean noValue;
        private boolean singleValue;
        private boolean betweenValue;
        private boolean listValue;
        private String typeHandler;

        protected Criterion(String condition) {
            super();
            this.condition = condition;
            this.typeHandler = null;
            this.noValue = true;
        }
    }
}