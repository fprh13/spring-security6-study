package com.example.TestSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

//    계층 권한 시
    @Bean
    public RoleHierarchy roleHierarchy() {

        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();

        hierarchy.setHierarchy("ROLE_C > ROLE_B\n" +
                "ROLE_B > ROLE_A");

        return hierarchy;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 1. 일반 적인 방식
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login", "/loginProc", "/join", "/joinProc").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated()
                );

        // 2. 걔층 권한 Role Hierarchy
//        http
//                .authorizeHttpRequests((auth) -> auth
//                        .requestMatchers("/login").permitAll()
//                        .requestMatchers("/").hasAnyRole("A")
//                        .requestMatchers("/manager").hasAnyRole("B")
//                        .requestMatchers("/admin").hasAnyRole("C")
//                        .anyRequest().authenticated()
//                );


        // 1. 특정한 html 로그인 페이지를 작성할 때 사용
        http
                .formLogin((auth) -> auth.loginPage("/login")
                        .loginProcessingUrl("/loginProc")
                        .permitAll()
                );

        // 2. 아이디와 비밀번호를 Base64 방식으로 브라우저의 Http 인증 헤더에 부착하여 서버측으로 요청을 보낸다.
//        일반 웹은 가끔
//        msa 구축할 때 유레카나 config 서버는 내부 적으로는 priavate 하게 통신하지만
//        더 엄격한 보안을 위해 사용한다.
//        http
//                .httpBasic(Customizer.withDefaults());



        // 다중 로그인 설정
        http
                .sessionManagement((auth) -> auth
                        // 동시 접속 인원 설정
                        .maximumSessions(1)
                        // 초과 했을 경우
                        // 초과시 새로운 로그인 차단 true
                        // 초과시 기존 세션 하나 삭제 false
                        .maxSessionsPreventsLogin(true));


        // 세션 보안 설정
        // none 보안 안함
        // newSession 로그인 시 세션 새로 생성
        // changeSessionId 로그인 시 동일한 세션에 대한 id 변경 (대부분 이것을 사용)
        http
                .sessionManagement((auth) -> auth
                        .sessionFixation().changeSessionId());

        // 개발 단계에서만 사용함
//        http
//                .csrf((auth) -> auth.disable());


        // post가 아닌 get요청으로 로그아웃 진행하기
        http
                .logout((auth) -> auth.logoutUrl("/logout")
                        .logoutSuccessUrl("/"));


        return http.build();
    }



    // 데이터 베이스를 사용할 수 없는 환경이거나
    // 소수의 회원 정보만 가지며 데이터 베이스라는 자원을 투자하기 힘든 경우 회원 가입 없는
    // inMemory 방식으로 유저를 저장
    // 회원을 삭제하거나 추가하는 방식은 없다.
//    @Bean
//    public UserDetailsService userDetailsService() {
//
//        UserDetails user1 = User.builder()
//                .username("user1")
//                .password(bCryptPasswordEncoder().encode("1234"))
//                .roles("C")
//                .build();
//
//        UserDetails user2 = User.builder()
//                .username("user2")
//                .password(bCryptPasswordEncoder().encode("1234"))
//                .roles("B")
//                .build();
//
//        return new InMemoryUserDetailsManager(user1, user2);
//    }
}
