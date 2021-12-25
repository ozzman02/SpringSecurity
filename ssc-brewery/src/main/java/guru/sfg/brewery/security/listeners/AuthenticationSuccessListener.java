package guru.sfg.brewery.security.listeners;

import guru.sfg.brewery.domain.security.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthenticationSuccessListener {

    @EventListener
    public void listen(AuthenticationSuccessEvent authenticationSuccessEvent) {
        log.debug("User logged in okay");
        if (authenticationSuccessEvent.getSource() instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authenticationSuccessEvent.getSource();
            if(token.getPrincipal() instanceof User){
                User user = (User) token.getPrincipal();
                log.debug("User name logged in: " + user.getUsername() );
            }
            if (token.getDetails() instanceof WebAuthenticationDetails){
                WebAuthenticationDetails details = (WebAuthenticationDetails) token.getDetails();
                log.debug("Source IP: " + details.getRemoteAddress());
            }
        }
    }

}
