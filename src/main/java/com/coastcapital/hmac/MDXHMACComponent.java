package com.coastcapital.hmac;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.mule.api.MuleEventContext;
import org.mule.api.MuleMessage;
import org.mule.api.expression.ExpressionManager;
import org.mule.api.lifecycle.Callable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class MDXHMACComponent implements Callable {
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static Logger log = LoggerFactory.getLogger(MDXHMACComponent.class);
	private String hmacSalt;

	/**
	 * @return the hmacSalt
	 */
	public String getHmacSalt() {
		return hmacSalt;
	}

	/**
	 * @param hmacSalt
	 *            the hmacSalt to set
	 */
	public void setHmacSalt(String hmacSalt) {
		this.hmacSalt = hmacSalt;
	}

	public Map<String, String> onCall(MuleEventContext eventContext) throws Exception {
		
		log.info("Called JavaComponent");
		
		// general setup for Java call
		final ExpressionManager mel = eventContext.getMuleContext().getExpressionManager();
		final MuleMessage message = eventContext.getMessage();
		
		Map<String, String> hashReturn = new LinkedHashMap<String, String>();

        // evaluate using MEL to get data of interest
		String hmac = (String) mel.evaluate (this.hmacSalt, null, message, false);

		// grab payload for manipulation
		final Object payload = message.getPayload();

		//Check to see if Payload is InputStream
		StringBuilder sb = null;
		if (payload instanceof InputStream) {
			byte[] payloadByteArray = IOUtils.toByteArray((InputStream) payload);
			sb = new StringBuilder(IOUtils.toString(payloadByteArray));

		} else if (payload instanceof String) {
			sb = new StringBuilder((String)payload);

		} else {
			throw new Exception();
		}

		String httpVerb = message.getInboundProperty("http.method");
		String md5Hash = DigestUtils.md5Hex(sb.toString());
		
		//Refactor to grab http.headers and cast to a map. Then use get for the assingment to string/whatever
		String contentTypeHeader = message.getInboundProperty("http.headers.Content-Type");
		String unixEpochTime = message.getInboundProperty("http.headers.date");
		String acceptHeader = message.getInboundProperty("http.headers.Accept");
		
		String resouceRequest = message.getInboundProperty("http.request");
		String mdxSessionKey = "";
		
		if (message.getInboundProperty("http.headers.MDX-Session-Key") == null) {
			mdxSessionKey = "";
		} 
		else if (message.getInboundProperty("http.headers.MDX-Session-Key") != null){
			mdxSessionKey = message.getInboundProperty("http.headers.MDX-Session-Key");
		} else {
			throw new Exception();
		}

		String combinedString = httpVerb.concat("\n").concat(md5Hash).concat("\n").concat(contentTypeHeader)
				.concat("\n").concat(unixEpochTime).concat("\n").concat(acceptHeader).concat("\n").concat(mdxSessionKey)
				.concat("\n").concat(resouceRequest);

		// Test String
		// combinedString =
		// "POST\ne9a179f879165fd64bdeaa57032d342f\napplication/vnd.moneydesktop.mdx.v5+xml\n1382975431\napplication/vnd.moneydesktop.mdx.v5+xml\n\n/sessions";

		// System.out.println(combinedString);
		// System.out.println(hmacSalt);

		// Decode Base64 Salt
		byte[] decoded = Base64.decodeBase64(hmacSalt);
		SecretKeySpec signingKey = new SecretKeySpec(decoded, HMAC_SHA1_ALGORITHM);
		Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
		mac.init(signingKey);
		byte[] finalBytes = mac.doFinal(combinedString.getBytes());
		String mdxHMAC = Hex.encodeHexString(finalBytes);
		
		//Add hashes to LinkedHashMap for return
		hashReturn.put("ContentMD5", md5Hash);
		hashReturn.put("MDX-HMAC", mdxHMAC);
		
		return hashReturn;
		
	}
}
