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

package de.gematik.dsr.gms.application.util;

import static io.quarkus.arc.ComponentsProvider.LOG;

import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class CSRDataConverter {

  private static final String CSR_NONCE_EXTENSION_OID_VALUE = "1.2.840.113549.1.9.7";

  public static final ASN1ObjectIdentifier CSR_NONCE_EXTENSION_OID =
      new ASN1ObjectIdentifier(CSR_NONCE_EXTENSION_OID_VALUE);

  private CSRDataConverter() {
    // Utility class
  }

  /** Method to convert a CSR in DER form to a PKCS10CertificationRequest */
  public static PKCS10CertificationRequest convertEncodedCsrToPKCS10PKCS10CertificationRequest(
      final String csrEncoded) {

    // 1. decode base64 CSR string
    final byte[] csrDecoded;
    try {
      csrDecoded = Base64.getDecoder().decode(csrEncoded);
    } catch (IllegalArgumentException e) {
      final UUID traceId = UUID.randomUUID();
      LOG.infof("%s Unable to decode CSR. %s", traceId, e.getLocalizedMessage());
      throw new GMServiceRuntimeException(GMServiceExceptionReason.CSR_INVALID, traceId);
    }

    // 2. parse CSR - DER format
    try (ASN1InputStream asn1InputStream = new ASN1InputStream(csrDecoded)) {
      return new PKCS10CertificationRequest(asn1InputStream.readAllBytes());
    } catch (IOException e) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s %s on parsing of CSR - %s",
          traceId, e.getClass().getSimpleName(), e.getLocalizedMessage());
      throw new GMServiceRuntimeException(GMServiceExceptionReason.CSR_ERROR, traceId);
    }
  }

  /** Method to extract nonce value form to a PKCS10CertificationRequest */
  public static byte[] extractNonceFromCSR(final PKCS10CertificationRequest csr) {
    return Arrays.stream(csr.getSubject().getRDNs(CSR_NONCE_EXTENSION_OID))
        .map(RDN::getFirst)
        .map(AttributeTypeAndValue::getValue)
        .findAny()
        .map(ASN1String.class::cast)
        .map(ASN1String::getString)
        .map((Base64.getDecoder()::decode))
        .orElse(new byte[0]);
  }
}
