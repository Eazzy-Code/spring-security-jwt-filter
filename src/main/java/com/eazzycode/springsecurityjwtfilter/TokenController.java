package com.eazzycode.springsecurityjwtfilter;

import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/token")
public class TokenController {

	@Value("classpath:rsakey.pem")
	private RSAPrivateKey privateKey;

	@PostMapping
	public String requestToken(@RequestBody TokenRequest tokenRequest) {
		Instant now = Instant.now();
		long expiry = 36000L;

		JWTClaimsSet claims = new JWTClaimsSet.Builder()
				.issuer("http://localhost:8080")
				.issueTime(new Date(now.toEpochMilli()))
				.expirationTime(new Date(now.plusSeconds(expiry).toEpochMilli()))
				.subject(tokenRequest.getUsername())
				.claim("scope", "ROLE_USER")
				.build();
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
		SignedJWT jwt = new SignedJWT(header, claims);
		return sign(jwt).serialize();
	}

	private SignedJWT sign(SignedJWT jwt) {
		try {
			jwt.sign(new RSASSASigner(this.privateKey));
			return jwt;
		}
		catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}

	private static class TokenRequest {

		private String username;
		private String password;

		public String getUsername() {
			return username;
		}

		public void setUsername(String username) {
			this.username = username;
		}

		public String getPassword() {
			return password;
		}

		public void setPassword(String password) {
			this.password = password;
		}
	}
}
