package guru.sfg.brewery.web.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.util.DigestUtils;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class PasswordEncodingTests {

    static final String PASSWORD1 = "password";
    static final String PASSWORD2 = "guru";
    static final String PASSWORD3 = "tiger";

    @Test
    void testBcrypt15() {
        PasswordEncoder bcrypt = new BCryptPasswordEncoder(15);
        System.out.println(bcrypt.encode(PASSWORD1));
        System.out.println(bcrypt.encode(PASSWORD2));
        System.out.println(bcrypt.encode(PASSWORD3));
    }

    @Test
    void testBcrypt() {
        PasswordEncoder bcrypt = new BCryptPasswordEncoder();
        System.out.println(bcrypt.encode(PASSWORD1));
        System.out.println(bcrypt.encode(PASSWORD2));
        System.out.println(bcrypt.encode(PASSWORD3));
    }

    @Test
    void testSha256() {
        PasswordEncoder sha256 = new StandardPasswordEncoder();
        System.out.println(sha256.encode(PASSWORD1));
        System.out.println(sha256.encode(PASSWORD2));
        System.out.println(sha256.encode(PASSWORD3));
    }

    @Test
    void testLdap() {
        PasswordEncoder ldap = new LdapShaPasswordEncoder();
        System.out.println(ldap.encode(PASSWORD1));
        System.out.println(ldap.encode(PASSWORD2));
        System.out.println(ldap.encode(PASSWORD3));

        String encodedPwd = ldap.encode(PASSWORD1);
        assertTrue(ldap.matches(PASSWORD1, encodedPwd));
    }

    @Test
    void testNoOp() {
        PasswordEncoder noOp = NoOpPasswordEncoder.getInstance();
        System.out.println(noOp.encode(PASSWORD1));
        System.out.println(noOp.encode(PASSWORD2));
        System.out.println(noOp.encode(PASSWORD3));
    }

    @Test
    void hashingExample() {
        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD1.getBytes()));
        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD1.getBytes()));

        String salted = PASSWORD1 + "ThisIsMySALTVALUE";
        System.out.println(DigestUtils.md5DigestAsHex(salted.getBytes()));
    }

}
