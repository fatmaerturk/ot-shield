package com.safetech.otshield;

import com.safetech.otshield.model.User;
import com.safetech.otshield.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
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

    // Seeds the initial admin ONLY if one with this email does not already exist.
    // Credentials come from config (admin.seed.email / admin.seed.password) so the
    // password is never hard-coded in a public repo. In prod, admin.seed.password
    // is empty unless ADMIN_SEED_PASSWORD is set, so no weak default admin is ever
    // created; a migrated database already has the admin (change its password in
    // the UI after migration).
    @Bean
    public CommandLineRunner commandLineRunner(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            @Value("${admin.seed.email:fatma.erturk@otshield.io}") String adminEmail,
            @Value("${admin.seed.password:}") String adminPassword) {
        return args -> {
            if (adminPassword == null || adminPassword.isBlank()) {
                System.out.println("admin.seed.password not set - skipping admin seed.");
                return;
            }
            if (userRepository.findByEmail(adminEmail).isEmpty()) {
                User user = new User();
                user.setEmail(adminEmail);
                user.setPassword(passwordEncoder.encode(adminPassword));
                user.setFullName("Fatma Erturk");
                user.setRole("ROLE_ADMIN");
                user.setIsAdmin(true);
                user.setIsActive(true);
                userRepository.save(user);
                System.out.println("Admin user seeded: " + adminEmail);
            }
        };
    }
} 