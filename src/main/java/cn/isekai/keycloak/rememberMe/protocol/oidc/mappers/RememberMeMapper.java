package cn.isekai.keycloak.rememberMe.protocol.oidc.mappers;

import org.keycloak.events.Details;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RememberMeMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, RememberMeMapper.class);
    }

    public static final String PROVIDER_ID = "oidc-remember-me-mapper";

    public RememberMeMapper() {
        super();
    }


    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Is Remember Me";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Maps whether user checked 'Remember Me'.";
    }

    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        token.getOtherClaims().put(Details.REMEMBER_ME, userSession.isRememberMe());
    }

    protected void setClaim(AccessTokenResponse accessTokenResponse, ProtocolMapperModel mappingModel,
                            UserSessionModel userSession, KeycloakSession keycloakSession,
                            ClientSessionContext clientSessionCtx) {
        accessTokenResponse.getOtherClaims().put(Details.REMEMBER_ME, userSession.isRememberMe());
    }

    public static ProtocolMapperModel create(String name, boolean accessToken, boolean idToken, boolean userInfo) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<>();
        if (accessToken) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        if (idToken) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        if (userInfo) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "false");
        mapper.setConfig(config);
        return mapper;
    }
}
