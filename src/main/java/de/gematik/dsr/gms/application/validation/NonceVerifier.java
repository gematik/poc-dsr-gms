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

import static de.gematik.dsr.gms.application.util.ByteArrayHelper.concatArrays;
import static de.gematik.dsr.gms.application.util.CertificateAndKeysDataConverter.getSha256Digest;

import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;
import java.util.function.Function;
import org.jboss.logging.Logger;

/** Builds and verifies nonce according the flow and client. */
public class NonceVerifier {

  private static final Logger LOG = Logger.getLogger(NonceVerifier.class);

  private static final byte[] INTEGRITY_BYTES = "INTEGRITY".getBytes(StandardCharsets.UTF_8);

  private static final byte[] KEYPAIR_MTLS_BYTES = "KEYPAIR_MTLS".getBytes(StandardCharsets.UTF_8);

  private static final byte[] CSR_MTLS_BYTES = "CSR_MTLS".getBytes(StandardCharsets.UTF_8);

  private static final byte[] ATTEST_DERIVED_BYTES = "1".getBytes(StandardCharsets.UTF_8);

  private static final byte[] PLAY_INTEGRITY_BYTES = "2".getBytes(StandardCharsets.UTF_8);

  public static final Function<String, byte[]> DEFAULT_DECODE_FUNCTION =
      Base64.getDecoder()::decode;

  private NonceVerifier() {}

  public static void verifyNonce(byte[] originalNonce, byte[] extractedNonce) {
    if (!MessageDigest.isEqual(originalNonce, extractedNonce)) {
      final UUID traceId = UUID.randomUUID();
      LOG.warnf("%s extracted nonce is not equal to generated one", traceId);
      throw new GMServiceRuntimeException(GMServiceExceptionReason.NONCE_INVALID, traceId);
    }
  }

  public static void verifyIntegrityNonce(String originalNonce, String extractedNonce) {
    byte[] integrityNonce = toIntegrityNonce(originalNonce, DEFAULT_DECODE_FUNCTION);
    verifyIntegrityVerdictNonce(integrityNonce, extractedNonce);
  }

  public static void verifyIntegrityVerdictNonce(
      byte[] integrityTokenNonce, String extractedNonce) {
    final String encodedIntegrityTokenNonce =
        Base64.getUrlEncoder().encodeToString(integrityTokenNonce);
    if (!encodedIntegrityTokenNonce.equals(extractedNonce)) {
      final UUID traceId = UUID.randomUUID();
      LOG.warnf("%s extracted integrity nonce is not equal to generated one", traceId);
      throw new GMServiceRuntimeException(GMServiceExceptionReason.NONCE_INVALID, traceId);
    }
  }

  public static byte[] toIntegrityNonce(String nonce, Function<String, byte[]> decodingFunction) {
    return toNonceWithSuffix(nonce, decodingFunction, INTEGRITY_BYTES);
  }

  public static void verifyKeypairMTLSNonce(String nonce, byte[] extractedChallenge) {
    byte[] keypairMTLSNonce = toKeypairMTLSNonce(nonce, DEFAULT_DECODE_FUNCTION);
    verifyNonce(keypairMTLSNonce, extractedChallenge);
  }

  public static byte[] toKeypairMTLSNonce(String nonce, Function<String, byte[]> decodingFunction) {
    return toNonceWithSuffix(nonce, decodingFunction, KEYPAIR_MTLS_BYTES);
  }

  public static void verifyCSRMTLSNonce(String nonce, byte[] extractedNonce) {
    byte[] csrMtlsNonce = toCSRMTLSNonce(nonce, DEFAULT_DECODE_FUNCTION);
    verifyNonce(csrMtlsNonce, extractedNonce);
  }

  public static byte[] toCSRMTLSNonce(String nonce, Function<String, byte[]> decodingFunction) {
    return toNonceWithSuffix(nonce, decodingFunction, CSR_MTLS_BYTES);
  }

  public static void verifyAttestDerivedNonce(String nonce, byte[] extractedChallenge) {
    byte[] attestDerivedNonce = toAttestDerivedNonce(nonce, DEFAULT_DECODE_FUNCTION);
    verifyNonce(attestDerivedNonce, extractedChallenge);
  }

  public static byte[] toAttestDerivedNonce(
      String nonce, Function<String, byte[]> decodingFunction) {
    return toNonceWithSuffix(nonce, decodingFunction, ATTEST_DERIVED_BYTES);
  }

  public static void verifyPlayIntegrityNonce(String nonce, String extractedNonce) {
    byte[] playIntegrityNonce = toPlayIntegrityNonce(nonce, DEFAULT_DECODE_FUNCTION);
    verifyIntegrityVerdictNonce(playIntegrityNonce, extractedNonce);
  }

  public static byte[] toPlayIntegrityNonce(
      String nonce, Function<String, byte[]> decodingFunction) {
    return toNonceWithSuffix(nonce, decodingFunction, PLAY_INTEGRITY_BYTES);
  }

  private static byte[] toNonceWithSuffix(
      String nonce, Function<String, byte[]> decoding, byte[] suffix) {
    byte[] decodedNonce = decoding.apply(nonce);
    byte[] nonceWithSuffix = concatArrays(decodedNonce, suffix);
    return getSha256Digest().digest(nonceWithSuffix);
  }
}
