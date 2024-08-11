package kolya.security.jwtauthentication;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;

public class AccessTokenFactory implements Function<Token, Token> {
    private Duration tokenTtl = Duration.ofMinutes(5);



    @Override
    public Token apply(Token token) {
        Instant createdAt = Instant.now();
        return new Token(token.id(), token.subject(), token.authorities()
                .stream()
                .filter(authority -> authority.startsWith("GRANT_"))
                .map(authority -> authority.replace("GRANT_", "")).toList(), createdAt, createdAt.plus(this.tokenTtl));
    }
    public void setTokenTtl(Duration tokenTtl) {
        this.tokenTtl = tokenTtl;
    }
}
