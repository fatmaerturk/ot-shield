package com.safetech.otshield;

import com.safetech.otshield.model.User;
import com.safetech.otshield.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
// Faz 4.5 needs @Scheduled for the watch-folder poller. Enabling it
// here is a no-op for the rest of the app until someone else drops in
// another @Scheduled bean.
@EnableScheduling
public class OTShieldApplication {
    public static void main(String[] args) {
        SpringApplication.run(OTShieldApplication.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.findByEmail("fatma.erturk@otshield.io").isEmpty()) {
                User user = new User();
                user.setEmail("fatma.erturk@otshield.io");
                user.setPassword(passwordEncoder.encode("Alex123@@@"));
                user.setFullName("Fatma Erturk");
                user.setRole("ROLE_ADMIN");
                user.setIsAdmin(true);
                user.setIsActive(true);
                userRepository.save(user);
                System.out.println("Test user created with admin role");
            }
        };
    }
} 