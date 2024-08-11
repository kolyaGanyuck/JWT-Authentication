package kolya.security.jwtauthentication;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.function.Function;

public class AccessTokenJwsStringSerializer implements Function<Token, String> {
    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenJwsStringSerializer.class);
    private final JWSSigner jwsSigner;
    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;


    public AccessTokenJwsStringSerializer(JWSSigner jwsSigner) {
        this.jwsSigner = jwsSigner;
    }

    public AccessTokenJwsStringSerializer(JWSSigner jwsSigner, JWSAlgorithm jwsAlgorithm) {
        this.jwsSigner = jwsSigner;
        this.jwsAlgorithm = jwsAlgorithm;
    }

    @Override
    public String apply(Token token) {
        SignedJWT signedJWT =
                new SignedJWT(new JWSHeader.Builder(this.jwsAlgorithm)
                        .keyID(token.id().toString()).build()

                        , new JWTClaimsSet.Builder().jwtID(token.id().toString())
                        .subject(token.subject())
                        .issueTime(Date.from(token.createdAt()))
                        .expirationTime(Date.from(token.expiresAt()))
                        .claim("Authorities", token.authorities())
                        .build());
        try {
            signedJWT.sign(this.jwsSigner);
            return signedJWT.serialize();
        }
        catch (JOSEException joseException){
            LOGGER.error(joseException.getMessage(), joseException);
        }
        return null;
    }

    public void setJwsAlgorithm(JWSAlgorithm jwsAlgorithm) {
        this.jwsAlgorithm = jwsAlgorithm;
    }
}
