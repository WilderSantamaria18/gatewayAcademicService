package pe.edu.idat.app_gateway.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final IJwtService jwtService;

    @Bean
    public FiltroJwtAuth filtroJwtAuth() {
        return new FiltroJwtAuth(jwtService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, FiltroJwtAuth filtroJwt) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .headers(headers -> headers.frameOptions(frame -> frame.disable()))
            .sessionManagement(session -> session.sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth ->
                auth
                    .requestMatchers(new AntPathRequestMatcher("/auth-service/api/auth/**")).permitAll()
                    .requestMatchers(new AntPathRequestMatcher("/auth-service/api/usuarios/**")).hasRole("ADMIN")
                    .requestMatchers(new AntPathRequestMatcher("/finance-service/api/finanzas/**")).authenticated()
                    .anyRequest().authenticated()
            )
            .addFilterBefore(filtroJwt, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}