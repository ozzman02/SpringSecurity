package guru.sfg.brewery.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
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

    @Bean
    PasswordEncoder passwordEncoder() {
        return new StandardPasswordEncoder();
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
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                })
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic();
    }

    /* In Memory Authentication using Authentication Fluent API. This is more elegant than using an UserDetailsService bean
        When setting a password encoder password must be replaced.

        Original configuration:
            - .password("{noop}password")
        With NoOp
            - .password("password")
        With LDAP
            - .password("{SSHA}l57TAjmtALxaKMK+ORG4w7YVCISxyb8QTyDgXQ==")
    */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("c433e80abc76d30fe75617c147941c28b9b810705578ae30c84f93b8d3c4028336262b1460763c4b")
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("76266b247e5720a894839fc12b313109e7332bc567b89fe5134bfbf264eed40431606b026d83f387")
                .roles("USER")
                .and()
                .withUser("scott")
                .password("65c8f495dc6d773cdccebfd402b35072688ac5f148ac2046400078ec3cc93fb5e22952bcc3fded59")
                .roles("CUSTOMER");
    }

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
