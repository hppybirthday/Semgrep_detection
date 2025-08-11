package com.gamestudio.xssdemo;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

public class GameChatPanel extends JPanel {
    private JTextArea chatArea;
    private JTextField inputField;
    private List<String> messages = new ArrayList<>();

    public GameChatPanel() {
        setLayout(new BorderLayout());
        chatArea = new JTextArea();
        chatArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(chatArea);
        add(scrollPane, BorderLayout.CENTER);

        JPanel inputPanel = new JPanel(new BorderLayout());
        inputField = new JTextField();
        JButton sendButton = new JButton("Send");
        inputPanel.add(inputField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);
        add(inputPanel, BorderLayout.SOUTH);

        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String message = inputField.getText();
                if (!message.isEmpty()) {
                    appendMessage("Player: " + message);
                    inputField.setText("");
                }
            }
        });
    }

    private void appendMessage(String message) {
        // 漏洞点：直接拼接HTML字符串导致XSS
        String htmlContent = "<div style='margin:5px;padding:8px;border-radius:5px;background:#f0f0f0'>" + message + "</div>";
        messages.add(htmlContent);
        updateChatDisplay();
    }

    private void updateChatDisplay() {
        StringBuilder html = new StringBuilder("<html><body style='margin:0;padding:0'>");
        for (String msg : messages) {
            html.append(msg);
        }
        html.append("</body></html>");
        chatArea.setText(html.toString());
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("Game Chat XSS Demo");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);
        frame.add(new GameChatPanel());
        frame.setVisible(true);
    }
}