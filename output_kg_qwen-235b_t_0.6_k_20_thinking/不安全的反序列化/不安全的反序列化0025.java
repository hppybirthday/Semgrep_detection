package com.bank.core.account;

import java.io.*;
import java.math.BigDecimal;
import java.util.Base64;

/**
 * 用户银行账户实体（领域层）
 */
public class UserAccount implements Serializable {
    private String accountId;
    private String ownerName;
    private BigDecimal balance;

    // 模拟账户持久化操作
    public void persist() {
        System.out.println("[持久化操作] 账户更新: " + this);
    }

    // 模拟转账操作
    public void transferTo(UserAccount target, BigDecimal amount) {
        if (this.balance.compareTo(amount) < 0) {
            throw new IllegalStateException("余额不足");
        }
        this.balance = this.balance.subtract(amount);
        target.balance = target.balance.add(amount);
        System.out.println("[转账成功] 从账户 " + this.accountId + " 转账 " + amount + " 到 " + target.accountId);
    }

    @Override
    public String toString() {
        return String.format("账户[%s] 姓名[%s] 余额[%.2f]", accountId, ownerName, balance.doubleValue());
    }
}

// 应用层代码
package com.bank.application;

import com.bank.core.account.UserAccount;
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.math.BigDecimal;
import java.util.Base64;

/**
 * 账户应用服务（应用层）
 */
public class AccountApplication extends HttpServlet {
    // 模拟反序列化转账请求
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String encodedData = request.getParameter("data");
        if (encodedData == null || encodedData.isEmpty()) {
            response.getWriter().write("缺少参数");
            return;
        }

        try {
            // 危险的反序列化操作
            UserAccount account = deserialize(encodedData);
            
            // 模拟转账操作（漏洞触发点）
            UserAccount targetAccount = new UserAccount();
            targetAccount.accountId = "ACC123456";
            targetAccount.ownerName = "攻击者账户";
            targetAccount.balance = BigDecimal.ZERO;
            
            // 如果反序列化的account对象被篡改，可能导致任意账户转账
            account.transferTo(targetAccount, new BigDecimal("999999.99"));
            
            account.persist();
            targetAccount.persist();
            
            response.getWriter().write("操作成功");
            
        } catch (Exception e) {
            response.getWriter().write("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // 不安全的反序列化实现
    private UserAccount deserialize(String encoded) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(encoded);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return (UserAccount) ois.readObject();
        }
    }

    // 模拟序列化生成攻击载荷
    public static void main(String[] args) throws Exception {
        UserAccount victimAccount = new UserAccount();
        victimAccount.accountId = "VICTIM123";
        victimAccount.ownerName = "受害者";
        victimAccount.balance = new BigDecimal("1000000.00");

        // 正常序列化（用于演示）
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(victimAccount);
        oos.flush();
        oos.close();
        
        String normalData = Base64.getEncoder().encodeToString(bos.toByteArray());
        System.out.println("正常数据: " + normalData);
        
        // 攻击者可能构造的恶意序列化数据（需要实际攻击工具生成）
        // 示例：使用ysoserial生成CommonsCollections5链
    }
}

// 配置类（基础设施层）
package com.bank.infrastructure;

import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AccountConfig {
    @Bean
    public ServletRegistrationBean<AccountApplication> accountServlet() {
        return new ServletRegistrationBean<>(new AccountApplication(), "/account/*");
    }
}