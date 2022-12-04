

/**
 * RFC JWS = https://datatracker.ietf.org/doc/html/rfc7515
 */
public class SesionUtil {

    public static void main(String role[]) throws Exception {
        
        System.out.println("VARIABLE = "+System.getProperty("APPS_GESTORA_AMBIENTE"));
        
//        PayloadAuth payloadAuth = new PayloadAuth();
//        payloadAuth.setCedulaIdentidad("6817702");
//        payloadAuth.setIssuer("GESTORA");
//        payloadAuth.getRoles().add("APROBADOR");
//        payloadAuth.getRoles().add("ENVIADOR");
//        
//        PrivateKey privateKey = SignatureUtil.readPriateKey(new File("D:\\apps\\seguridad\\claves\\private2.pem"));
//
//        String token = SesionUtil.generarToken(privateKey, payloadAuth);
//
//        System.out.println(token);
    }
}