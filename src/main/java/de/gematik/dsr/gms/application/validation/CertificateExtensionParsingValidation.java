/*
 * Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.dsr.gms.application.validation;

import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.jboss.logging.Logger;

/** Provides validation and parsing for certificate extension. */
public class CertificateExtensionParsingValidation
    implements Validation<List<X509Certificate>, ASN1Sequence> {

  private static final Logger LOG = Logger.getLogger(CertificateExtensionParsingValidation.class);

  private final String oid;

  /**
   * Creates {@link CertificateExtensionParsingValidation} for the given extension identifier.
   *
   * @param oid Object Identifier for some certificate extension.
   */
  public CertificateExtensionParsingValidation(String oid) {
    this.oid = oid;
  }

  /**
   * Makes lookup of the certificate extension with the given instance {@link #oid} and converts it
   * to {@link ASN1Sequence}
   *
   * @param x509Certificates certificate chain with the searched extension.
   * @return the found extension as {@link ASN1Sequence}
   * @throws GMServiceRuntimeException occurs if extension is not found or not parsable to sequence.
   */
  @Override
  public ASN1Sequence evaluate(List<X509Certificate> x509Certificates) {
    byte[] extension = findExtension(x509Certificates);

    try (ASN1InputStream asn1InputStream = new ASN1InputStream(extension)) {
      byte[] derSequenceBytes = ((ASN1OctetString) asn1InputStream.readObject()).getOctets();
      try (ASN1InputStream seqInputStream = new ASN1InputStream(derSequenceBytes)) {
        return (ASN1Sequence) seqInputStream.readObject();
      }
    } catch (IOException e) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s Failed to parse sequence data from certificate extension for OID: %s", traceId, oid);
      throw new GMServiceRuntimeException(
          ValidationExceptionReason.NOT_PARSABLE_EXTENSION_VALUE, traceId, e);
    }
  }

  private byte[] findExtension(List<X509Certificate> x509Certificates) {
    Optional<byte[]> extensionsBytes =
        x509Certificates.stream()
            .map(x509Certificate -> x509Certificate.getExtensionValue(oid))
            .filter(bytes -> bytes != null && bytes.length > 0)
            .findFirst();

    if (extensionsBytes.isEmpty()) {
      final UUID traceId = UUID.randomUUID();
      LOG.warnf("%s Failed to find certificate extension for OID: %s", traceId, oid);
      throw new GMServiceRuntimeException(
          ValidationExceptionReason.MISSING_CERTIFICATE_EXTENSION_VALUE, traceId);
    }
    return extensionsBytes.get();
  }
}
