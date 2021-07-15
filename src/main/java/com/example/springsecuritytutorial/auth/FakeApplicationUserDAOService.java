package com.example.springsecuritytutorial.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.springsecuritytutorial.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDAOService implements ApplicationUserDAO {

    private final PasswordEncoder passwordEncoder;


    @Autowired
    public FakeApplicationUserDAOService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        passwordEncoder.encode("password"),
                        "bhone",
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        passwordEncoder.encode("password"),
                        "linda",
                        STUDENT.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),

                new ApplicationUser(
                        passwordEncoder.encode("password"),
                        "tim",
                        ADMINTRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )

        );

        return applicationUsers;
    }
}
