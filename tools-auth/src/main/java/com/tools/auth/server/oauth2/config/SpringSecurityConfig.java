package com.tools.auth.server.oauth2.config;

import com.tools.common.core.utils.PermitUrlProperties;
import com.tools.common.core.utils.encrypt.PasswordEncorder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringSecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncorder passwordEncorder;

    @Autowired
    private PermitUrlProperties permitUrlProperties;


    /**
     * ??????AuthenticationManager?????????????????????????????????????????????
     *
     * @param authenticationConfiguration
     * @return
     * @throws Exception
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().antMatchers("/oauth/user/login", permitUrlProperties.getIgnored().toString());
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                // ?????? token???????????? csrf
                .csrf().disable()
                // ?????? token???????????? session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // ?????? jwtAuthError ?????????????????????????????????
//                .exceptionHandling().authenticationEntryPoint(jwtAuthError).accessDeniedHandler(jwtAuthError).and()
                // ????????????????????????
                .authorizeRequests(authorize -> authorize
                        // ????????????
                        .antMatchers("/**").permitAll()
                        .antMatchers("/**").permitAll()
                        // ???????????????????????????????????????
                        .anyRequest().authenticated()
                )
                // ?????? JWT ????????????JWT ????????????????????????????????????????????????
//                .addFilterBefore(authFilter(), UsernamePasswordAuthenticationFilter.class)
                // ????????????????????????????????????????????????springAuthUserService
//                .userDetailsService(userDetailsService)
                .build();
    }

    @Bean
    public void userDetailsManager(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncorder);
    }

    /**
     * ??????????????????(CORS)
     *
     * @return
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }


}
