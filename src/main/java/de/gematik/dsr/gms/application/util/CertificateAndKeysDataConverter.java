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

import static de.gematik.dsr.gms.application.util.ClasspathResourcesReader.extensionPathMatcherPredicate;
import static de.gematik.dsr.gms.application.util.ClasspathResourcesReader.readFromClasspathResources;

import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.idp.crypto.CryptoLoader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.function.Predicate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.jboss.logging.Logger;

public class CertificateAndKeysDataConverter {
  private static final Logger LOG = Logger.getLogger(CertificateAndKeysDataConverter.class);

  private static final String[] CERTIFICATE_FILE_EXTENSIONS = {"pem", "cert", "crt", "der"};

  private CertificateAndKeysDataConverter() {}

  public static List<X509Certificate> decodePemCertificateChain(List<String> certificateChain) {
    return certificateChain.stream()
        .map(Base64.getDecoder()::decode)
        .map(CryptoLoader::getCertificateFromPem)
        .toList();
  }

  public static List<X509Certificate> loadCertificates(String... certificatePaths)
      throws IllegalArgumentException, NullPointerException {
    final Predicate<String> pathPredicate =
        extensionPathMatcherPredicate(CERTIFICATE_FILE_EXTENSIONS);
    List<byte[]> bytes = readFromClasspathResources(pathPredicate, certificatePaths);
    return bytes.stream().map(CryptoLoader::getCertificateFromPem).toList();
  }

  public static byte[] calculatePublicKeyFingerprint(PublicKey publicKey) {
    SubjectPublicKeyInfo subjectPublicKeyInfo =
        SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    return calculatePublicKeyFingerprint(subjectPublicKeyInfo);
  }

  public static byte[] calculatePublicKeyFingerprint(X509Certificate certificate) {
    return calculatePublicKeyFingerprint(certificate.getPublicKey());
  }

  public static byte[] calculatePublicKeyFingerprint(SubjectPublicKeyInfo publicKeyInfo) {
    final byte[] publicKeyBytes = publicKeyInfo.getPublicKeyData().getBytes();
    final MessageDigest sha256Digest = getSha256Digest();
    return sha256Digest.digest(publicKeyBytes);
  }

  public static MessageDigest getSha256Digest() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf("%s %s", traceId, e.getLocalizedMessage());
      throw new GMServiceRuntimeException(
          GMServiceExceptionReason.ALGORITHM_INITIALISATION_ERROR, traceId);
    }
  }
}
