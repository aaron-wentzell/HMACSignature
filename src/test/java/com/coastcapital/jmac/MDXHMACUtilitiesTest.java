package com.coastcapital.jmac;

import com.coastcapital.hmac.MDXHMACUtilities;
import org.junit.Test;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

/**
 * Created by aaronwentzell on 2017-12-04.
 */
public class MDXHMACUtilitiesTest {

    @Test
    public void positiveTestMD5() {
       String payload =
               "<?xml version=\"1.0\"?>\n<mdx version=\"5.0\">\n  <session>\n    <userkey><![CDATA[the-userkey]]></userkey>\n  </session>\n</mdx>\n";

       String md5Hash = MDXHMACUtilities.createMD5Hash(payload);

        assertEquals("Payload MD5 not returning as expected","e9a179f879165fd64bdeaa57032d342f",md5Hash);
    }

  @Test
    public void positveTestHMACSignature() {
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
        assertNotNull("HMAC Signature is null",hmacSignature);
        assertEquals("HMAC Signature Not Equal","e47928dcd29e494116961ad12884c8fd7aae07f2",hmacSignature);
    }

    @Test
    public void negativeTestMD5() {
        String payload =
                "<?xml version=\"1.0\"?>\n<mdx version=\"5.0\">\n  <session>\n    <userkey><![CDATA[the-userkey]]>I will break the test</userkey>\n  </session>\n</mdx>\n";

        String md5Hash = MDXHMACUtilities.createMD5Hash(payload);
        assertNotNull("Payload MD5 is null",md5Hash);
        assertNotEquals("Payload MD5 should not match","e9a179f879165fd64bdeaa57032d342f",md5Hash);
    }

    @Test
    public void negativeTestHMACSignature() {
        String httpVerb = "POST";
        String md5Hash = "e9a179f879165fd64bdeaa57032d342f";
        String contentTypeHeader = "application/vnd.moneydesktop.mdx.v5+xml";
        String unixEpochTime = "1382975431";
        String acceptHeader="application/vnd.moneydesktop.mdx.v5+xml";
        String mdxSessionKey="I Will break the test case";
        String resouceRequest="/sessions";
        String hmacSalt = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo3ODkwMTI=";

        String hmacSignature = "";
        try{
            hmacSignature=MDXHMACUtilities.createHMACSignature(httpVerb,md5Hash,contentTypeHeader,unixEpochTime,acceptHeader,mdxSessionKey,resouceRequest,hmacSalt);
        } catch(Exception ex){
            assertEquals("Exception Occured in HMAC Signature",1,2);
        }
        assertNotNull("HMAC Signature is null",hmacSignature);
        assertNotEquals("HMAC Signature should not match","e47928dcd29e494116961ad12884c8fd7aae07f2",hmacSignature);
    }

    @Test
    public void combinedTest() {

        //Grab MD5 Hash
        String payload =
                "<?xml version=\"1.0\"?>\n<mdx version=\"5.0\">\n  <session>\n    <userkey><![CDATA[the-userkey]]></userkey>\n  </session>\n</mdx>\n";
        String md5Hash = MDXHMACUtilities.createMD5Hash(payload);
        assertEquals("Payload MD5 not returning as expected","e9a179f879165fd64bdeaa57032d342f",md5Hash);

        //Grab HMAC Hash
        String httpVerb = "POST";
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
        assertNotNull("HMAC Signature is null",hmacSignature);
        assertEquals("HMAC Signature Not Equal","e47928dcd29e494116961ad12884c8fd7aae07f2",hmacSignature);
    }

    @Test
    public void positiveCompareTest(){
        //Grab MD5 Hash
        String payload =
                "<?xml version=\"1.0\"?>\n<mdx version=\"5.0\">\n  <session>\n    <userkey><![CDATA[the-userkey]]></userkey>\n  </session>\n</mdx>\n";
        String md5Hash = MDXHMACUtilities.createMD5Hash(payload);

        //Grab HMAC Hash
        String httpVerb = "POST";
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

        //Compare
        boolean bool = false;
        try {
            bool = MDXHMACUtilities.compareHashes(md5Hash,hmacSignature,payload,httpVerb,contentTypeHeader,unixEpochTime,acceptHeader,mdxSessionKey,resouceRequest,hmacSalt);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assertTrue("Hashes are not equal",bool);


    }

}
