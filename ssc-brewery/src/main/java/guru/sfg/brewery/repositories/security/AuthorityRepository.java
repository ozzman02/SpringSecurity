package guru.sfg.brewery.repositories.security;

import guru.sfg.brewery.domain.security.Authority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/*
    How does Spring Data JPA manage transactions?
    Unless you've initialized a transaction in your code, Spring Data JPA will implicitly create a transaction when repository methods are called.
    This can later cause you issues with lazily loaded references - if you try to access them outside the transactional scope.
*/
@Repository
public interface AuthorityRepository extends JpaRepository<Authority, Integer> {
}
