package com.e_gineering.salesforce.oauth;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

public class KeyPairUtils {

  public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }

  public static String privateKeyAsString(PrivateKey privateKey) throws IOException {
    return writePemObjectBytes("PRIVATE KEY", privateKey.getEncoded());
  }

  public static String generateCertificateAsString(KeyPair keyPair) throws IOException, GeneralSecurityException, OperatorCreationException {
    X509Certificate certificate = generateCertificate(keyPair);
    return writePemObjectBytes("CERTIFICATE", certificate.getEncoded());
  }

  private static String writePemObjectBytes(String s, byte[] bytes) throws IOException {
    var pemObject = new PemObject(s, bytes);

    var byteStream = new ByteArrayOutputStream();
    var pemWriter = new PemWriter(new OutputStreamWriter(byteStream));
    pemWriter.writeObject(pemObject);
    pemWriter.close();
    return byteStream.toString();
  }

  private static X509Certificate generateCertificate(KeyPair keyPair) throws GeneralSecurityException, IOException, OperatorCreationException {
    final Instant now = Instant.now();
    final Date notBefore = Date.from(now);
    final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));

    final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
    final X500Name x500Name = new X500Name("CN=" + "cn=Testing");
    final X509v3CertificateBuilder certificateBuilder =
      new JcaX509v3CertificateBuilder(x500Name,
        BigInteger.valueOf(now.toEpochMilli()),
        notBefore,
        notAfter,
        x500Name,
        keyPair.getPublic())
        .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
        .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(keyPair.getPublic()))
        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

    return new JcaX509CertificateConverter()
      .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
  }

  private static SubjectKeyIdentifier createSubjectKeyId(final PublicKey publicKey) throws OperatorCreationException {
    final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    final DigestCalculator digCalc =
      new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

    return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
  }

  private static AuthorityKeyIdentifier createAuthorityKeyId(final PublicKey publicKey)
    throws OperatorCreationException {
    final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    final DigestCalculator digCalc =
      new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

    return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
  }
}
