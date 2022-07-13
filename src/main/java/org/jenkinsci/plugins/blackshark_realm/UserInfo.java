package org.jenkinsci.plugins.blackshark_realm;

import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collection;

public class UserInfo implements Serializable {

    public String mail;
    public String displayName;
    public Collection<String> memberOf;
    public Collection<GrantedAuthority> groups;

    public UserInfo(String mail, String displayName, Collection<String> memberOf, Collection<GrantedAuthority> groups) {
        this.mail = mail;
        this.displayName = displayName;
        this.memberOf = memberOf;
        this.groups = groups;
    }

}
