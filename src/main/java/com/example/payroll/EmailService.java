package com.example.payroll;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Service
public class EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    public EmailService(JavaMailSender mailSender, TemplateEngine templateEngine) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }

    @Async
    public void sendWelcomeEmail(String to, String username) throws MessagingException {
        Context context = new Context();
        context.setVariable("username", username);
        String htmlContent = templateEngine.process("welcome-email", context);

        sendEmail(to, "Welcome to Our Platform!", htmlContent);
    }

    @Async
    public void sendAdminNotification(String to, String message) throws MessagingException {
        Context context = new Context();
        context.setVariable("message", message);
        String htmlContent = templateEngine.process("admin-notification", context);

        sendEmail(to, "New User Registered", htmlContent);
    }

    private void sendEmail(String to, String subject, String htmlContent) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);
        mailSender.send(message);
    }
}
