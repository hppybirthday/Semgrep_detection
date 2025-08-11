package com.jsh.erp.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.TypeReference;
import com.jsh.erp.datasource.entities.AccountHead;
import com.jsh.erp.datasource.mappers.AccountHeadMapperEx;
import com.jsh.erp.exception.BusinessRunTimeException;
import com.jsh.erp.exception.JshException;
import com.jsh.erp.utils.PageUtils;
import com.jsh.erp.utils.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class AccountService {
    private Logger logger = LoggerFactory.getLogger(AccountService.class);

    @Resource
    private AccountHeadMapperEx accountHeadMapperEx;
    @Resource
    private UserService userService;
    @Resource
    private LogService logService;

    public AccountHead getAccountHead(long id) throws Exception {
        AccountHead result = null;
        try {
            result = accountHeadMapperEx.selectByPrimaryKey(id);
        } catch (Exception e) {
            JshException.readFail(logger, e);
        }
        return result;
    }

    @Transactional(value = "transactionManager", rollbackFor = Exception.class)
    public int updateAccountHeadAndDetail(JSONObject obj, HttpServletRequest request) throws Exception {
        // 漏洞点：直接反序列化用户输入的JSON为AccountHead对象
        AccountHead accountHead = JsonUtils.jsonToObject(obj.toJSONString(), AccountHead.class);
        int result = 0;
        try {
            result = accountHeadMapperEx.updateByPrimaryKeySelective(accountHead);
            logService.insertLog("账户头信息",
                    new StringBuffer("编辑").append(accountHead.getName()).toString(), request);
        } catch (Exception e) {
            JshException.writeFail(logger, e);
        }
        return result;
    }

    @Transactional(value = "transactionManager", rollbackFor = Exception.class)
    public int addAccountHeadAndDetail(JSONObject obj, HttpServletRequest request) throws Exception {
        AccountHead accountHead = JsonUtils.jsonToObject(obj.toJSONString(), AccountHead.class);
        int result = 0;
        try {
            result = accountHeadMapperEx.insertSelective(accountHead);
            logService.insertLog("账户头信息",
                    new StringBuffer("新增").append(accountHead.getName()).toString(), request);
        } catch (Exception e) {
            JshException.writeFail(logger, e);
        }
        return result;
    }

    public List<AccountHead> getAccountHeadsByType(String type) throws Exception {
        List<AccountHead> list = null;
        try {
            list = accountHeadMapperEx.selectByType(type);
        } catch (Exception e) {
            JshException.readFail(logger, e);
        }
        return list;
    }

    public static class JsonUtils {
        // 漏洞分析：反序列化时未限制类型
        public static <T> T jsonToObject(String json, Class<T> clazz) {
            if (StringUtil.isEmpty(json)) {
                return null;
            }
            try {
                // 危险操作：fastjson自动类型解析
                return JSON.parseObject(json, clazz);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid JSON data");
            }
        }

        public static <T> T jsonToList(String json, TypeReference<T> typeReference) {
            if (StringUtil.isEmpty(json)) {
                return null;
            }
            try {
                return JSON.parseObject(json, typeReference);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid JSON data");
            }
        }

        // 误导性安全检查（未实际启用）
        private static boolean isSafeType(Class<?> clazz) {
            // 白名单检查被注释掉
            // return clazz.getPackage().getName().startsWith("com.jsh.erp.datasource.entities");
            return true;
        }
    }
}