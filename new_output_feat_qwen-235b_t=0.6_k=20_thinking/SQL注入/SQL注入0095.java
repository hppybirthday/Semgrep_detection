// Controller层
@RestController
@RequestMapping("/api/chat/clients")
@Tag(name = "ChatClientController", description = "聊天客户端管理")
public class ChatClientController {

    @Autowired
    private ChatClientService chatClientService;

    @Operation(summary = "批量删除客户端")
    @DeleteMapping("/delete")
    public CommonResult<Void> deleteClients(@RequestParam("ids") List<String> clientIds) {
        chatClientService.deleteClients(clientIds);
        return CommonResult.success();
    }
}

// Service层
@Service
public class ChatClientService {

    @Autowired
    private ClientMapper clientMapper;

    public void deleteClients(List<String> clientIds) {
        if (clientIds == null || clientIds.isEmpty()) {
            throw new IllegalArgumentException("Client IDs cannot be empty");
        }
        
        // 将客户端ID列表转换为逗号分隔字符串
        String ids = String.join(",", clientIds);
        
        // 调用MyBatis映射接口
        clientMapper.deleteClients(ids);
    }
}

// Mapper接口
@Mapper
public interface ClientMapper {
    @Delete("DELETE FROM clients WHERE id IN (\${ids})")
    void deleteClients(@Param("ids") String ids);
}

// 实体类
public class Client {
    private Long id;
    private String username;
    // 省略getter/setter
}

// 响应封装类
class CommonResult<T> {
    private int code;
    private String message;
    private T data;
    public static <T> CommonResult<T> success() {
        CommonResult<T> result = new CommonResult<>();
        result.setCode(200);
        return result;
    }
    // 省略其他字段实现
}