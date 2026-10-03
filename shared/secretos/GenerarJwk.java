import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

/**
 * Genera la clave de firma de los tokens (RSA 2048, uso firma) y la escribe en la salida
 * estandar como JWK con la parte privada. La lee el auth de JWT_KEY_LOCATIONS. Es el
 * snippet del README, en fichero, con la MISMA biblioteca que la lee (nimbus-jose-jwt).
 *
 * Uso: java -cp nimbus-jose-jwt.jar GenerarJwk.java <kid>
 */
public class GenerarJwk {
    public static void main(String[] args) throws Exception {
        System.out.print(new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(args[0])
                .generate()
                .toJSONString());
    }
}
