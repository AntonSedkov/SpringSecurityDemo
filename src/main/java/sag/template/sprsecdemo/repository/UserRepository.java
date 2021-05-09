package sag.template.sprsecdemo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sag.template.sprsecdemo.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {

    Optional<User> findByEmail(String email);

}
