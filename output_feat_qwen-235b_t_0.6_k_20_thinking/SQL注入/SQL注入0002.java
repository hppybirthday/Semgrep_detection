package com.example.chatapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@SpringBootApplication
public class ChatApplication {
    public static void main(String[] args) {
        SpringApplication.run(ChatApplication.class, args);
    }
}

@RestController
@RequestMapping("/messages")
class MessageController {
    @Resource
    private MessageService messageService;

    @DeleteMapping("/delete")
    public String deleteMessages(@RequestParam String clients) {
        // 函数式编程风格处理参数
        List<String> ids = Arrays.stream(clients.split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .collect(Collectors.toList());
        
        // 直接拼接字符串参数
        String idList = String.join(",", ids);
        messageService.removeMessages(idList);
        return "Deleted";
    }
}

interface MessageService {
    void removeMessages(String ids);
}

@Service
class MessageServiceImpl implements MessageService {
    @Resource
    private MessageMapper messageMapper;

    // 函数式编程风格实现
    @Override
    public void removeMessages(String ids) {
        // 直接将用户输入传递给MyBatis-Plus的removeByIds
        // 危险：未使用参数化查询，直接拼接字符串
        messageMapper.removeByIds(ids);
    }
}

interface MessageMapper extends BaseMapper<Message> {
    // 使用MyBatis-Plus的批量删除方法
    // 实际执行时会将参数直接拼接进SQL
    void removeByIds(String ids);
}

class Message {
    private Long id;
    private String content;
    // getter/setter
}
// 生成的SQL实际为：DELETE FROM message WHERE id IN (传入的原始字符串)
// 攻击者可通过传入"1,2,3 UNION SELECT * FROM users"窃取数据