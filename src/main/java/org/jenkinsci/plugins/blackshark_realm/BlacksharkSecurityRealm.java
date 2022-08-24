package org.jenkinsci.plugins.blackshark_realm;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import jenkins.security.LastGrantedAuthoritiesProperty;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
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

import javax.crypto.Cipher;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;


public class BlacksharkSecurityRealm extends AbstractPasswordBasedSecurityRealm {
    private static final Logger LOGGER = Logger.getLogger(BlacksharkSecurityRealm.class.getName());

    public final String loginApi;
    public final String publicKey;

    @DataBoundConstructor
    public BlacksharkSecurityRealm(String loginApi, String publicKey) {
        this.loginApi = StringUtils.trim(loginApi);
        this.publicKey = StringUtils.trim(publicKey);
    }


    private UserInfo getUserInfo(String username, String password, boolean needpw) throws IOException {
        Map paramMap = new HashMap();
        if (StringUtils.isEmpty(password) && needpw) {
            LOGGER.warning("password is empty");
            throw new BadCredentialsException("password is null");
        }

        if (StringUtils.isEmpty(username)) {
            LOGGER.warning("username is empty");
            throw new BadCredentialsException("username is null");
        }

        if (StringUtils.contains(username, "@")) {
            String[] split = StringUtils.split(username, "@");
            username = split[0];
        }
        username = username.toLowerCase();
        LOGGER.info("the new username is " + username);

        if (StringUtils.isEmpty(password) && !needpw) {
            paramMap.put("checktype", "2");
        }

        String url = joinParam(StringUtils.trim(loginApi), paramMap);
        LOGGER.info("will send to this url: " + url);
        HttpPost httpPost = new HttpPost(url);


        JSONObject jsonObject = new JSONObject();
        jsonObject.put("userName", encrypt(username));
        jsonObject.put("passWord", encrypt(password));


        StringEntity entity = new StringEntity(jsonObject.toString(), "utf-8");
        entity.setContentEncoding("UTF-8");
        entity.setContentType("application/json");
        httpPost.setEntity(entity);
        CloseableHttpClient client = HttpClients.createDefault();
        CloseableHttpResponse response = client.execute(httpPost);
        String bodyAsString = EntityUtils.toString(response.getEntity());
        LOGGER.info("bodyAsString: " + bodyAsString);
        JSONObject obj = JSONObject.fromObject(bodyAsString);

        if (obj == null) {
            LOGGER.warning("the request is null");
            throw new BadCredentialsException("request is null");
        }

        int status = obj.getInt("status");
        String msg = obj.getString("msg");
        JSONObject data = obj.getJSONObject("data");
        if (status != 0) {
            LOGGER.warning("the request status is not 0");
            throw new BadCredentialsException(msg);
        }
        if (data == null || data.isNullObject()) {
            LOGGER.info("the data is null");
            throw new BadCredentialsException("data is null");
        }

        boolean isMember = data.getBoolean("isMember");
        if (!isMember) {
            LOGGER.warning("the request isMember is not true");
            throw new BadCredentialsException(msg);
        }
        JSONObject userInfo = data.getJSONObject("userInfo");
        String displayName = userInfo.getString("DisplayName");
        String email = userInfo.getString("Email");
        JSONArray memberOf = userInfo.getJSONArray("MemberOf");

        Set<String> member = new HashSet<>();
        for (Object o : memberOf) {
            member.add(o.toString());
        }

        List<GrantedAuthority> groups = loadGroups(username);
        for (Object o : member) {
            groups.add(new SimpleGrantedAuthority(o.toString()));
        }

        UserInfo userinfo = new UserInfo(email, displayName, member, groups);

        return userinfo;
    }

    private String encrypt(String inData) {
        try {

            String publicKeyPEM = publicKey
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPEM);

            RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            String outData = Base64.getEncoder().encodeToString(cipher.doFinal(inData.getBytes(StandardCharsets.UTF_8)));
            return outData;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }

    }

    @Override
    protected UserDetails authenticate2(String username, String password) throws AuthenticationException {
        try {
            UserInfo userInfo = getUserInfo(username, password, true);
            List<GrantedAuthority> groups = loadGroups(username);
            groups.addAll(userInfo.groups);
            BlacksharkUserDetail user = new BlacksharkUserDetail(username, password, userInfo.displayName, userInfo.mail, groups);
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
        authorities.add(new SimpleGrantedAuthority(username));
        return authorities;
    }

    @Override
    public UserDetails loadUserByUsername2(String username) throws UsernameNotFoundException {
        try {
            BlacksharkUserDetail user;
            List<GrantedAuthority> groups = loadGroups(username);
            hudson.model.User u = hudson.model.User.getById(username, false);
            if (u == null) {
                UserInfo userInfo = getUserInfo(username, "", false);
                groups.addAll(userInfo.groups);
                user = new BlacksharkUserDetail(username, "", userInfo.displayName, userInfo.mail, groups);
            } else {
                Mailer.UserProperty mailerUserProperty = u.getProperty(Mailer.UserProperty.class);
                String mail = username + "@blackshark.com";
                if (mailerUserProperty != null) {
                    mail = mailerUserProperty.getAddress();
                }
                LastGrantedAuthoritiesProperty lastGrantedAuthoritiesProperty = u.getProperty(LastGrantedAuthoritiesProperty.class);
                if (lastGrantedAuthoritiesProperty != null) {
                    Collection<? extends GrantedAuthority> authorities2 = lastGrantedAuthoritiesProperty.getAuthorities2();
                    groups.addAll(authorities2);
                }
                user = new BlacksharkUserDetail(username, "", u.getDisplayName(), mail, groups);
            }
            return user;
        } catch (Exception e) {
            throw new UsernameNotFoundException("Failed", e);
        }
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
