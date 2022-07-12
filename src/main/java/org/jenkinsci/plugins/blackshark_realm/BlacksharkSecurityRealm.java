package org.jenkinsci.plugins.blackshark_realm;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;


public class BlacksharkSecurityRealm extends AbstractPasswordBasedSecurityRealm {
    private static final Logger LOGGER = Logger.getLogger(BlacksharkSecurityRealm.class.getName());

    public final String loginApi;

    @DataBoundConstructor
    public BlacksharkSecurityRealm(String loginApi) {
        this.loginApi = loginApi;
    }

    @Override
    protected UserDetails authenticate2(String username, String password) throws AuthenticationException {
        try {
            if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
                throw new BadCredentialsException("username password is null");
            }
            if (StringUtils.contains(username, "@")) {
                String[] split = StringUtils.split(username, "@");
                username = split[0];
            }
            username = username.toLowerCase();

            String userName = Base64.getEncoder().encodeToString(username.getBytes("utf-8"));
            String passWord = Base64.getEncoder().encodeToString(password.getBytes("utf-8"));
            Map paramMap = new HashMap();
            paramMap.put("username", userName);
            paramMap.put("password", passWord);

            String url = joinParam(loginApi, paramMap);
            HttpGet httpGet = new HttpGet(url);

            CloseableHttpClient client = HttpClients.createDefault();
            CloseableHttpResponse response = client.execute(httpGet);
            String bodyAsString = EntityUtils.toString(response.getEntity());
            JSONObject obj = JSONObject.fromObject(bodyAsString);

            if (obj == null) {
                throw new BadCredentialsException("request is null");
            }

            int status = obj.getInt("status");
            String msg = obj.getString("msg");
            JSONObject data = obj.getJSONObject("data");
            if (status != 0) {
                throw new BadCredentialsException(msg);
            }
            boolean isMember = data.getBoolean("isMember");
            if (!isMember) {
                throw new BadCredentialsException(msg);
            }
            JSONObject userInfo = data.getJSONObject("userInfo");
            String displayName = userInfo.getString("DisplayName");
            String email = userInfo.getString("Email");
            JSONArray memberOf = userInfo.getJSONArray("MemberOf");

            List<GrantedAuthority> groups = loadGroups(username);
            for (Object o : memberOf) {
                groups.add(new SimpleGrantedAuthority(o.toString()));
            }
            BlacksharkUserDetail user = new BlacksharkUserDetail(username, password, displayName, email, groups);
            updateUserDetails(user);
            return user;
        } catch (IOException e) {
            throw new AuthenticationServiceException("Failed", e);
        }
    }

    public void updateUserDetails(BlacksharkUserDetail d) {
        hudson.model.User u = hudson.model.User.getById(d.getUsername(), true);
        u.setFullName(d.getDisplayName());

        Mailer.UserProperty mailerUserProperty = u.getProperty(Mailer.UserProperty.class);
        try {
            u.addProperty(new Mailer.UserProperty(d.getMail()));
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    protected List<GrantedAuthority> loadGroups(String username) throws AuthenticationException {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(AUTHENTICATED_AUTHORITY2);
        return authorities;
    }

    @Override
    public UserDetails loadUserByUsername2(String username) throws UsernameNotFoundException {
        List<GrantedAuthority> groups = loadGroups(username);
        BlacksharkUserDetail user = new BlacksharkUserDetail(username, "", username, username + "@blackshark.com", groups);
        return user;
    }

    @Override
    public GroupDetails loadGroupByGroupname2(String groupname, boolean fetchMembers) throws UsernameNotFoundException {
        BlacksharkGroupDetail group = new BlacksharkGroupDetail(groupname);
        return group;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return "Authenticate via blackshark login api";
        }
    }

    public static String joinParam(String root, List<NameValuePair> list) {
        try {
            URI uri = new URIBuilder(root).addParameters(list).build();
            return uri.toString();
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        return root;
    }

    public static String joinParam(String root, String name, List<String> values) {
        List<NameValuePair> list = values.stream().map(p ->
                new BasicNameValuePair(name, p)).collect(Collectors.toList());
        return joinParam(root, list);
    }

    public static String joinParam(String root, Map<String, String> values) {
        List<NameValuePair> list = values.entrySet().stream().map(p ->
                new BasicNameValuePair(p.getKey(), p.getValue())).collect(Collectors.toList());
        return joinParam(root, list);
    }
}
