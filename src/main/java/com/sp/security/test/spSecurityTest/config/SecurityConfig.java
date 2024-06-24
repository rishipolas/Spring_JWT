package com.sp.security.test.spSecurityTest.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    // Refer the spring security in youtube channel : EmbarkX | Learn Programming
    // https://www.youtube.com/watch?v=CTdPnaWmSuY&list=PLxhSr_SLdXGOpdX60nHze41CvExvBOn09&index=4


    @Autowired
    DataSource dataSource;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((auths) -> auths
                                .requestMatchers("/h2-console/**").permitAll()
                                .anyRequest()
//                        .requestMatchers("/public/**")
                        .authenticated()
                );

                //h2 db do
                http.headers(hds->hds.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin).disable());
                http.csrf(csrf ->csrf.ignoringRequestMatchers("/h2-console/**"));

        http.httpBasic(withDefaults());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

//    /**
//     * non persist implementation mainly intended for testing...!!!
//     * @return UserDetailsService object
//     */
//    @Bean
//    public UserDetailsService userDetails() {
//        UserDetails user1 = User.withUsername("user")
//                .password("{noop}user") // hey {noop} tell spring password should safe as plain text
//                .roles("USER").build();
//
//        UserDetails admin1 = User.withUsername("admin")
//                .password("{noop}admin") // hey {noop} tell spring password should safe as plain text
//                .roles("ADMIN").build();
//
//        return new InMemoryUserDetailsManager(user1, admin1);
//    }


    /**
     *  persist implementation using H2 Database mainly intended for testing...!!!
     * @return UserDetailsService object
     */
    @Bean
    public UserDetailsService userDetails() {
        UserDetails user1 = User.withUsername("user")
                .password(passwordEncoder().encode("user")) // hey {noop} tell spring password should safe as plain text
                .roles("USER").build();

        UserDetails admin1 = User.withUsername("admin")
                .password(passwordEncoder().encode("admin")) // hey {noop} tell spring password should safe as plain text
                .roles("ADMIN").build();

        // Database configurations
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user1);
        jdbcUserDetailsManager.createUser(admin1);

        // do google search spring security GitHub  then -> search in GitHub users.ddl in search box

        return jdbcUserDetailsManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
