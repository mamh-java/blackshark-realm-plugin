package org.jenkinsci.plugins.blackshark_realm;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.logging.Logger;

public class BlacksharkUserDetail extends User {
    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = Logger.getLogger(BlacksharkUserDetail.class.getName());

    private final String displayName;
    private final String mail;

    public BlacksharkUserDetail(String username, String password, String displayName, String mail,
                                Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.displayName = displayName;
        this.mail = mail;
    }

    public BlacksharkUserDetail(String username, String password, String displayName, String mail,
                                boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked,
                                Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.displayName = displayName;
        this.mail = mail;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getMail() {
        return mail;
    }
}
