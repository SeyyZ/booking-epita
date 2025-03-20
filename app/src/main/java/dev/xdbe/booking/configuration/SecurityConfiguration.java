package dev.xdbe.booking.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth
            .requestMatchers("/dashboard").hasRole("ADMIN")
            .anyRequest().permitAll()
            )
            .formLogin(withDefaults())
            .logout(logout -> logout.logoutUrl("/logout").permitAll())
            // Step 3: Add login form
            .csrf((csrf) -> csrf
                .ignoringRequestMatchers("/h2-console/*")
            )
            .headers(headers -> headers.frameOptions().disable())
            .build();
    }

    // Step 3: add InMemoryUserDetailsManager
    @Bean
    public UserDetailsService users() {
        UserDetails adminUser = User.builder()
            .username("admin")
            .password("{bcrypt}$2a$10$NBSzmliyfosnI2YL7AF.4ebyMViZqqwPE8axz2kP0EJ6DKemy2Qfy") 
            .roles("ADMIN")
            .build();

        UserDetails regularUser = User.builder()
            .username("user")
            .password("{bcrypt}$2a$10$NBSzmliyfosnI2YL7AF.4ebyMViZqqwPE8axz2kP0EJ6DKemy2Qfy")
            .roles("USER")
            .build();

        return new InMemoryUserDetailsManager(adminUser, regularUser);
    }
}