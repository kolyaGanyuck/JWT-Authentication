package kolya.security.jwtauthentication;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.function.Function;

public class RefreshTokenJweStringSerializer implements Function<Token, String> {
    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenJwsStringSerializer.class);

    private JWEEncrypter jweEncrypter;

    private JWEAlgorithm algorithm = JWEAlgorithm.DIR;
    private EncryptionMethod method = EncryptionMethod.A128GCM;

    public RefreshTokenJweStringSerializer(JWEEncrypter jweEncrypter, JWEAlgorithm algorithm, EncryptionMethod method) {
        this.jweEncrypter = jweEncrypter;
        this.algorithm = algorithm;
        this.method = method;
    }

    public RefreshTokenJweStringSerializer(JWEEncrypter jweEncrypter) {
        this.jweEncrypter = jweEncrypter;
    }

    @Override
    public String apply(Token token) {
        EncryptedJWT encryptedJWT =
                new EncryptedJWT(new JWEHeader.Builder(this.algorithm, this.method)
                        .keyID(token.id().toString()).build()

                        , new JWTClaimsSet.Builder().jwtID(token.id().toString())
                        .subject(token.subject())
                        .issueTime(Date.from(token.createdAt()))
                        .expirationTime(Date.from(token.expiresAt()))
                        .claim("Authorities", token.authorities())
                        .build());
        try {
            encryptedJWT.encrypt(this.jweEncrypter);
            return encryptedJWT.serialize();
        } catch (JOSEException joseException) {
            LOGGER.error(joseException.getMessage(), joseException);
        }
        return null;
    }
}
