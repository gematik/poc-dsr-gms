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

package de.gematik.dsr.gms.application.ios;

import static de.gematik.dsr.gms.application.ios.IOSValidationReason.INVALID_COUNTER;
import static de.gematik.dsr.gms.application.ios.IOSValidationReason.INVALID_RP_ID;
import static de.gematik.dsr.gms.application.util.ByteArrayHelper.concatArrays;
import static de.gematik.dsr.gms.application.util.CertificateAndKeysDataConverter.getSha256Digest;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import de.gematik.dsr.gms.application.MasterDataRepository;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;
import org.jboss.logging.Logger;

public abstract class AbstractIOSValidation {

  protected final Logger logger = Logger.getLogger(getClass());

  protected final ObjectMapper cborObjectMapper;

  protected final Function<String, byte[]> decodingFunction;

  protected final MessageDigest sha256Digest;

  protected final MasterDataRepository masterDataRepository;

  protected AbstractIOSValidation(
      final Function<String, byte[]> decodingFunction,
      final MasterDataRepository masterDataRepository) {
    this.cborObjectMapper =
        new CBORMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    this.sha256Digest = getSha256Digest();
    this.decodingFunction = decodingFunction;
    this.masterDataRepository = masterDataRepository;
  }

  /**
   * Point 6 of Verify the Attestation Chapter: Compute the SHA256 hash of your app’s App ID, and
   * verify that it’s the same as the authenticator data’s RP ID hash.
   *
   * <p>Point 4 of Verify the Assertion Chapter: Compute the SHA256 hash of the client’s App ID, and
   * verify that it matches the RP ID in the authenticator data.
   *
   * @param rpId data to validate
   */
  protected void verifyRpId(byte[] rpId) {
    Optional<byte[]> applicationIdSha256Hash =
        masterDataRepository.getAvailableAppIds().stream()
            .map(MasterDataRepository.AppId::buildAppId)
            .map(p -> p.getBytes(StandardCharsets.UTF_8))
            .map(sha256Digest::digest)
            .filter(d -> MessageDigest.isEqual(d, rpId))
            .findAny();

    if (applicationIdSha256Hash.isEmpty()) {
      UUID traceId = UUID.randomUUID();
      logger.errorf("%s RP ID hash doesn't match to any known application ID", traceId);
      throw new GMServiceRuntimeException(INVALID_RP_ID, traceId);
    }
  }

  /**
   * Point 7 of Verify the Attestation Chapter: Verify that the authenticator data’s counter field
   * equals 0.
   *
   * <p>Point 5 of Verify the Assertion Chapter: Verify that the authenticator data’s counter value
   * is greater than the value from the previous assertion, or greater than 0 on the first
   * assertion.
   *
   * @param counter data to validate
   */
  protected void verifyCounter(int counter) {
    if (!counterPredicate().test(counter)) {
      UUID traceId = UUID.randomUUID();
      logger.errorf("%s Counter %d doesn't appreciate expected value", traceId, counter);
      throw new GMServiceRuntimeException(INVALID_COUNTER, traceId);
    }
  }

  protected abstract Predicate<Integer> counterPredicate();

  public byte[] generateChallenge(String nonce, String sub) {
    byte[] nonceIntegrity = toNonceByteArray(nonce);
    byte[] decodedSub = decodingFunction.apply(sub);
    return concatArrays(nonceIntegrity, decodedSub);
  }

  /**
   * Create clientDataHash as the SHA256 hash of the one-time challenge your server sends to your
   * app before performing the attestation, and append that hash to the end of the authenticator
   * data (authData from the decoded object).
   *
   * <p>Generate a new SHA256 hash of the composite item to create nonce.
   *
   * @param authData authData from the decoded object
   * @param challenge obtained challenge
   * @return sha256Hash of the composite item
   */
  protected byte[] generateClientDataHash(byte[] authData, byte[] challenge) {
    byte[] sha256Challenge = sha256Digest.digest(challenge);
    return sha256Digest.digest(concatArrays(authData, sha256Challenge));
  }

  protected abstract byte[] toNonceByteArray(String nonce);
}
