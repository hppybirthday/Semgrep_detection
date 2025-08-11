package com.gamestudio.maintenance;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 游戏维护任务过滤器
 * 处理游戏服务器维护相关的定时任务
 */
public class GameMaintenanceFilter implements Filter {
    private static final String MAINTENANCE_PATH = "/admin/maintenance";
    private static final Map<String, String> VALID_COMMANDS = new HashMap<>();

    static {
        VALID_COMMANDS.put("backup", "backup_game_data.sh");
        VALID_COMMANDS.put("restart", "restart_game_server.sh");
    }

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String path = httpRequest.getRequestURI();

        if (path.startsWith(MAINTENANCE_PATH)) {
            String action = httpRequest.getParameter("action");
            String user = httpRequest.getParameter("user");
            String password = httpRequest.getParameter("password");
            String db = httpRequest.getParameter("db");

            if (action != null && VALID_COMMANDS.containsKey(action)) {
                try {
                    GameCommandExecutor executor = new GameCommandExecutor();
                    // 构建并执行维护命令
                    executor.executeMaintenanceCommand(
                            VALID_COMMANDS.get(action),
                            user,
                            password,
                            db
                    );
                } catch (Exception e) {
                    // 记录异常但继续处理请求
                    e.printStackTrace();
                }
            }
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {}

    /**
     * 验证参数格式
     * @param params 参数列表
     * @return 验证结果
     */
    private boolean validateParams(String... params) {
        for (String param : params) {
            if (param == null || param.isEmpty()) {
                return false;
            }
        }
        return true;
    }
}

class GameCommandExecutor {
    void executeMaintenanceCommand(String commandName, String user, String password, String db)
            throws ExecuteException, IOException {
        
        // 构建命令参数
        Map<String, String> params = new HashMap<>();
        params.put("user", user);
        params.put("password", password);
        params.put("db", db);
        
        // 创建命令行对象
        CommandLine commandLine = new CommandLine(commandName);
        
        // 添加参数到命令行
        for (Map.Entry<String, String> entry : params.entrySet()) {
            commandLine.addArgument("--" + entry.getKey() + "=" + entry.getValue());
        }
        
        // 执行命令
        DefaultExecutor executor = new DefaultExecutor();
        executor.execute(commandLine);
    }
}