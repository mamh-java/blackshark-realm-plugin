package org.jenkinsci.plugins.blackshark_realm;

import hudson.security.GroupDetails;

import java.util.logging.Logger;

public class BlacksharkGroupDetail extends GroupDetails {
    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = Logger.getLogger(BlacksharkGroupDetail.class.getName());

    private String name;

    public BlacksharkGroupDetail(String name) {
        super();
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }
}
