package com.coastcapital.hmac;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HMACHash {

    public static String generateHash (String secretKey, String message) throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance("HmacSHA1");
        byte[] decoded = Base64.decodeBase64(secretKey);
        SecretKeySpec secret = new SecretKeySpec(decoded, "HmacSHA1");
        mac.init(secret);
        byte[] digest = mac.doFinal(message.getBytes());
        String hmac = Hex.encodeHexString(digest);
        return hmac;

    }
}
