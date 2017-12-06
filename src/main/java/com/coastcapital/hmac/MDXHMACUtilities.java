package com.coastcapital.hmac;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


//import org.apache.logging.log4j.Logger;
//import org.apache.logging.log4j.LogManager;

/**
 * Created by aaronwentzell on 2017-12-04.
 */
public class MDXHMACUtilities {
    //private static final Logger logger = LogManager.getLogger(com.coastcapital.hmac.MDXHMACUtilities.class);
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    /**
     *
     * @param payload the inbound http body
     * @return MD5 hash of the inbound http body
     */
    public static String createMD5Hash (String payload) {
        String digest = DigestUtils.md5Hex(payload);
        return digest;
    }

    /**
     *
     * @param httpVerb The http method being used
     * @param md5Hash The MD5 hash of the payload
     * @param contentTypeHeader http content type
     * @param unixEpochTime date converted to unix epoch
     * @param acceptHeader http accept header
     * @param mdxSessionKey session key if required for MX Endpoint
     * @param resouceRequest http resource requested
     * @param hmacSalt
     * @return Hash built to spec for MX
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static String createHMACSignature(String httpVerb, String md5Hash, String contentTypeHeader, String unixEpochTime, String acceptHeader, String mdxSessionKey, String resouceRequest, String hmacSalt)
            throws NoSuchAlgorithmException, InvalidKeyException{

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

        //Test string and console logs
        //combinedString = "POST\ne9a179f879165fd64bdeaa57032d342f\napplication/vnd.moneydesktop.mdx.v5+xml\n1382975431\napplication/vnd.moneydesktop.mdx.v5+xml\n\n/sessions";
        //System.out.println(combinedString);
        //System.out.println(hmacSalt);

        byte[] decoded = Base64.decodeBase64(hmacSalt);
        SecretKeySpec signingKey = new SecretKeySpec(decoded, HMAC_SHA1_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
        mac.init(signingKey);
        byte[] finalBytes = mac.doFinal(combinedString.getBytes());
        String returnStr = Hex.encodeHexString(finalBytes);
        return returnStr;
    }

    /**
     *
     * @param inboundMD5Hash inbound hash from the inbound request
     * @param inboundHMACHash inbound hash from the inbound request
     * @param payload inbound payload
     * @param httpVerb inbound http method
     * @param contentTypeHeader inbound content type header
     * @param unixEpochTime inbound date converted to unix epoch time
     * @param acceptHeader inbound http accept header
     * @param mdxSessionKey inbound session key if required
     * @param resouceRequest inbound http resource request
     * @param hmacSalt
     * @return boolean indicator of message integrity
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    public static boolean compareHashes(String inboundMD5Hash, String inboundHMACHash, String payload,String httpVerb, String contentTypeHeader, String unixEpochTime, String acceptHeader, String mdxSessionKey, String resouceRequest, String hmacSalt) throws InvalidKeyException, NoSuchAlgorithmException {

        boolean bool;

        String md5Hash = createMD5Hash(payload);
        String hmacHash = createHMACSignature(httpVerb,md5Hash,contentTypeHeader,unixEpochTime,acceptHeader,mdxSessionKey,resouceRequest,hmacSalt);

        if (md5Hash.equals(inboundMD5Hash)){

            if(hmacHash.equals(inboundHMACHash)){
                bool = true;
                return bool;
            } else {
                bool = false;
                return bool;
            }

        } else {
            bool = false;
            return bool;
        }
    }

}
