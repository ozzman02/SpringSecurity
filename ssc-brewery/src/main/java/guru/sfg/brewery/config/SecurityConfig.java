package guru.sfg.brewery.config;

import guru.sfg.brewery.security.JpaUserDetailsService;
import guru.sfg.brewery.security.RestHeaderAuthFilter;
import guru.sfg.brewery.security.RestUrlAuthFilter;
import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /* NoOp Password Encoder
    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }*/

    /* LDAP Password Encoder
    @Bean
    PasswordEncoder passwordEncoder() {
        return new LdapShaPasswordEncoder();
    }*/

    /* SHA256 Password Encoder
    @Bean
    PasswordEncoder passwordEncoder() {
        return new StandardPasswordEncoder();
    }*/

    /* BCryptPasswordEncoder
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }*/

    /* DelegatingPasswordEncoder
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }*/

    public RestHeaderAuthFilter restHeaderAuthFilter(AuthenticationManager authenticationManager) {
        RestHeaderAuthFilter filter = new RestHeaderAuthFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    public RestUrlAuthFilter restUrlAuthFilter(AuthenticationManager authenticationManager){
        RestUrlAuthFilter filter = new RestUrlAuthFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return SfgPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /*
        The difference between /* & /** is that the second matches the entire directory tree, including subdirectories,
        whereas /* only matches at the level it's specified at.

        Example:

            @Override
            protected void configure(HttpSecurity http) throws Exception {
                // ...
                .antMatchers(HttpMethod.GET, "/**").permitAll
                .antMatchers(HttpMethod.POST, "/*").permitAll
                // ...
            }

            In this configuration any "Get" request will be permitted (So, all this urls match text with pattern "/**".), for example:

                /book
                /book/20
                /book/20/author

            Permitted urls for "Post" (Urls below match with "/*"):

                /book
                /magazine
    */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable();
        http
                .addFilterBefore(restHeaderAuthFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
        http
                .addFilterBefore(restUrlAuthFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/h2-console/**").permitAll()
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll();
                })
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic();

        /* H2 Console configuration */
        http.headers().frameOptions().sameOrigin();

    }

    /* In Memory Authentication using Authentication Fluent API. This is more elegant than using an UserDetailsService bean
        When setting a password encoder password must be replaced.

        Original configuration:
            - .password("{noop}password") USER role

        With NoOp
            - .password("password") USER role

        With LDAP
            - .password("{SSHA}l57TAjmtALxaKMK+ORG4w7YVCISxyb8QTyDgXQ==") USER role

        With SHA256
            - .password("76266b247e5720a894839fc12b313109e7332bc567b89fe5134bfbf264eed40431606b026d83f387") USER role

        With BCrypt
            - .password("$2a$10$ltO.Q32U5Twf00daKEgQSuC9sKIkr8a7zXYPDqn3oG.K63IZcvpMG") USER role

        With Delegating Password Encoder
            - .password("{bcrypt}$2a$10$sIryYMfq8BA9gupSlmPsXOwNUtum0LbDyoJV6XZi4PGbOMVO6LYh.") ADMIN role
            - .password("{sha256}a7eda2f4237fb0724d0770cca0af05038c837c009850fa743bd3ad7b6ca5fc23c2437b72ab5e958f") USER role
            - .password("{ldap}{SSHA}6tPxjqd+J9VyQXBnhVR9ffyJbwQZRYbn9bXEdQ==") CUSTOMER role

        With Custom Delegating Password Encoder
            - .password("{bcrypt}$2a$10$KEBTpOyvlhraKTsaP0yctuxJkEndbFab7cWV9JDZS2NE6cZnaGrHu") ADMIN role
            - .password("{bcrypt}$2a$10$Cb2KNiI4KSpDOMy9h82zGufO0ZdDLQIjP7Qzy4wqPBYQv88OwYp0O") USER role
            - .password("{bcrypt15}$2a$15$aS40Yic3n0PnLyIvchEGyO295AWVs9IQYV65K0TkSO7./lX7.5s8C") CUSTOMER role

    */
    /* In Memory Authentication
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("{bcrypt}$2a$10$KEBTpOyvlhraKTsaP0yctuxJkEndbFab7cWV9JDZS2NE6cZnaGrHu")
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("{bcrypt}$2a$10$Cb2KNiI4KSpDOMy9h82zGufO0ZdDLQIjP7Qzy4wqPBYQv88OwYp0O")
                .roles("USER")
                .and()
                .withUser("scott")
                .password("{bcrypt15}$2a$15$aS40Yic3n0PnLyIvchEGyO295AWVs9IQYV65K0TkSO7./lX7.5s8C")
                .roles("CUSTOMER");
    }*/

    /*  This is one way of using the Custom User Details Service.
    @Autowired
    JpaUserDetailsService jpaUserDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(this.jpaUserDetailsService).passwordEncoder(passwordEncoder());
    } */

    /*@Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("spring")
                .password("guru")
                .roles("ADMIN")
                .build();

        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }*/

}
