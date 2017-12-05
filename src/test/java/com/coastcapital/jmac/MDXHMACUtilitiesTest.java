package com.coastcapital.jmac;

import com.coastcapital.hmac.MDXHMACUtilities;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;

/**
 * Created by aaronwentzell on 2017-12-04.
 */
public class MDXHMACUtilitiesTest {

    @Test
    public void testMD5() {
       String payload =
               "<?xml version=\"1.0\"?>\n<mdx version=\"5.0\">\n  <session>\n    <userkey><![CDATA[the-userkey]]></userkey>\n  </session>\n</mdx>\n";

       String md5Hash = MDXHMACUtilities.createMD5Hash(payload);

        assertEquals("Payload MD5 not returning as expected","e9a179f879165fd64bdeaa57032d342f",md5Hash);
    }

    @Test
    public void testHMACSignature() {
        String httpVerb = "POST";
        String md5Hash = "e9a179f879165fd64bdeaa57032d342f";
        String contentTypeHeader = "application/vnd.moneydesktop.mdx.v5+xml";
        String unixEpochTime = "1382975431";
        String acceptHeader="application/vnd.moneydesktop.mdx.v5+xml";
        String mdxSessionKey="";
        String resouceRequest="/sessions";
        String hmacSalt = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo3ODkwMTI=";

        String hmacSignature = "";
        try{
            hmacSignature=MDXHMACUtilities.createHMACSignature(httpVerb,md5Hash,contentTypeHeader,unixEpochTime,acceptHeader,mdxSessionKey,resouceRequest,hmacSalt);
        } catch(Exception ex){
            assertEquals("Exception Occured in HMAC Signature",1,2);
        }

        assertEquals("HMAC Signature Not Equal","e47928dcd29e494116961ad12884c8fd7aae07f2",hmacSignature);
    }
}
