package com.coastcapital.hmac;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Formatter;

//import org.apache.logging.log4j.Logger;
//import org.apache.logging.log4j.LogManager;

/**
 * Created by aaronwentzell on 2017-12-04.
 */
public class MDXHMACUtilities {
    //private static final Logger logger = LogManager.getLogger(com.coastcapital.hmac.MDXHMACUtilities.class);
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    /**
     * This method is used to create an MD5Hash out of a method payload
     */
    public static String createMD5Hash (String payload) {
        String digest = DigestUtils.md5Hex(payload);
        return digest;
    }

    /**
     * This method is used to create the HMAC Signature
     */
    public static String createHMACSignature(String httpVerb, String md5Hash, String contentTypeHeader, String unixEpochTime, String acceptHeader, String mdxSessionKey, String resouceRequest, String hmacSalt)
        throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{

        String combinedString = httpVerb.concat("\n")
                .concat(md5Hash)
                .concat("\n")
                .concat(contentTypeHeader)
                .concat("\n")
                .concat(unixEpochTime)
                .concat("\n")
                .concat(acceptHeader)
                .concat("\n")
                .concat(mdxSessionKey)
                .concat("\n").concat(resouceRequest);

        combinedString = "POST\ne9a179f879165fd64bdeaa57032d342f\napplication/vnd.moneydesktop.mdx.v5+xml\n1382975431\napplication/vnd.moneydesktop.mdx.v5+xml\n\n/sessions";

        System.out.println(combinedString);
        System.out.println(hmacSalt);


        SecretKeySpec signingKey = new SecretKeySpec(hmacSalt.getBytes(), HMAC_SHA1_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
        mac.init(signingKey);
        byte[] finalBytes = mac.doFinal(combinedString.getBytes());


        String returnStr = Hex.encodeHexString(finalBytes);
        return returnStr;
    }


    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();

        for (byte b : bytes) {
            formatter.format("%02x", b);
        }

        return formatter.toString();
    }


}
