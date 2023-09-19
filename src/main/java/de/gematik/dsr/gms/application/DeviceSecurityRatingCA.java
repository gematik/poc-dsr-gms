/*
 * Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.dsr.gms.application;

import de.gematik.dsr.gms.application.util.CSRDataConverter;
import jakarta.enterprise.context.ApplicationScoped;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/** Temporary CA, to generate a CSR and receive a certificate */
@ApplicationScoped
public class DeviceSecurityRatingCA {

  @ConfigProperty(name = "ca.key.path")
  PrivateKey privateKey;

  @ConfigProperty(name = "ca.cert.path")
  X509Certificate caCertificate;

  /** create base64 DER certificate from base64 CSR */
  public String issueCertificate(final String csrEncoded) {
    final PKCS10CertificationRequest csr =
        CSRDataConverter.convertEncodedCsrToPKCS10PKCS10CertificationRequest(csrEncoded);

    final X509Certificate certificate = issueCertificate(csr);
    try {
      return Base64.getEncoder().encodeToString(certificate.getEncoded());
    } catch (CertificateEncodingException e) {
      throw new GmsCryptoException(e);
    }
  }

  private X509Certificate issueCertificate(final PKCS10CertificationRequest csr) {

    final SecureRandom random = new SecureRandom();
    final BigInteger serialNumber = new BigInteger(128, random);

    final Date notBefore = Date.from(Instant.now());
    final Date notAfter = Date.from(notBefore.toInstant().plus(365, ChronoUnit.DAYS));

    try {
      // this is important in order for nginx to identify the matching ca based on client cert
      final X500Name issuer = new JcaX509CertificateHolder(caCertificate).getSubject();

      final X509v3CertificateBuilder certificateBuilder =
          new JcaX509v3CertificateBuilder(
              issuer,
              serialNumber,
              notBefore,
              notAfter,
              csr.getSubject(),
              csr.getSubjectPublicKeyInfo());

      final ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(privateKey);
      final X509CertificateHolder certificateHolder = certificateBuilder.build(signer);
      return new JcaX509CertificateConverter().getCertificate(certificateHolder);
    } catch (Exception e) {
      throw new GmsCryptoException(e);
    }
  }
}
