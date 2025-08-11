import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.StringReader;

public class GameChatPanel extends JFrame {
    private final JTextArea chatDisplay = new JTextArea();
    private final JTextField inputField = new JTextField();
    private final JScrollPane scrollPane = new JScrollPane(chatDisplay);

    public GameChatPanel() {
        super("Game Chat - Vulnerable XSS Demo");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 400);
        setLocationRelativeTo(null);
        
        chatDisplay.setEditable(false);
        chatDisplay.setContentType("text/html");
        chatDisplay.setText("<html><body style='font-family:Arial'>Welcome to the game chat!<br>");
        
        inputField.addActionListener((e) -> processInput());
        
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(inputField, BorderLayout.SOUTH);
        add(panel);
        
        setVisible(true);
    }

    private void processInput() {
        String userInput = inputField.getText();
        if (userInput.isEmpty()) return;
        
        // Vulnerable code:直接拼接用户输入到HTML内容中
        String safeHtml = "<br><div style='color:blue'>Player: " + userInput + "</div>";
        chatDisplay.setText(chatDisplay.getText() + safeHtml);
        
        // 模拟攻击向量：如果用户输入包含<script>标签会被执行
        // 示例攻击载荷：<script>alert('XSS Attack!');</script>
        
        inputField.setText("");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new GameChatPanel());
    }
}