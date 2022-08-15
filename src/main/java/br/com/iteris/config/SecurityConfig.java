package br.com.iteris.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration

@EnableGlobalMethodSecurity(
        prePostEnabled = true,
        securedEnabled = true,
        jsr250Enabled = true)
public class SecurityConfig {

/*
Nessa classe, estamos indicando ao Spring, quais endpoints serão publicos e quais irão exigir autenticação

Deixamos os endpoints do swagger publicos e também o endpoint de login.
O endpoint de login, obviamente, precisa ser público.
Caso contrário, o usuário não vai conseguir logar.
*/

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception { http.csrf().disable();

        http
                .authorizeHttpRequests((authz) -> authz
                        .antMatchers("/login").permitAll()
                        .antMatchers("/swagger-ui/**").permitAll()
                        .antMatchers("/v3/**").permitAll()
                        .anyRequest().authenticated() );

// Também estamos indicando ao Spring, que faremos uma autenticação Stateless.

        http = http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and();

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}