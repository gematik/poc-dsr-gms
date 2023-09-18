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

package de.gematik.dsr.gms.application.ios.attestation;

import static de.gematik.dsr.gms.application.util.ByteArrayHelper.compareByteArrayLists;
import static de.gematik.dsr.gms.application.util.ByteArrayHelper.toStringByteArrayList;

import de.gematik.idp.crypto.CryptoLoader;
import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Parsed from CBOR-Format part of 'attestation' - Attestation Statement.
 *
 * @param x5c certificate chain
 * @param receipt current receipt bytes
 * @see de.gematik.dsr.gms.application.ios.receipt.IOSReceipt
 */
public record AttestationStatement(List<byte[]> x5c, byte[] receipt) implements Serializable {

  public List<X509Certificate> parsedX509Certificates() {
    return x5c().stream().map(CryptoLoader::getCertificateFromPem).toList();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    AttestationStatement attStmt = (AttestationStatement) o;
    return compareByteArrayLists(x5c, attStmt.x5c) && Arrays.equals(receipt, attStmt.receipt);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(x5c);
    result = 31 * result + Arrays.hashCode(receipt);
    return result;
  }

  @Override
  public String toString() {
    return "AttStmt{"
        + "x5c="
        + toStringByteArrayList(x5c)
        + ", receipt="
        + Arrays.toString(receipt)
        + '}';
  }
}
