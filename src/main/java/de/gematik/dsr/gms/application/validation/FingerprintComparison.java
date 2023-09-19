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

import static de.gematik.dsr.gms.application.Validation.ValidationExceptionReason.FINGERPRINT_COMPARISON_FAILURE;

import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;
import org.jboss.logging.Logger;

public class FingerprintComparison {

  private static final Logger LOG = Logger.getLogger(FingerprintComparison.class);

  private FingerprintComparison() {}

  public static void compare(final byte[] publicKeyFingerprint, final String deviceKey) {
    // compare hash values sub and public key fingerprint of leaf certificate.
    final boolean hashesMatch =
        MessageDigest.isEqual(publicKeyFingerprint, Base64.getDecoder().decode(deviceKey));

    if (!hashesMatch) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s hashed public key of leaf certificate not equal to subject public key fingerprint",
          traceId);
      throw new GMServiceRuntimeException(FINGERPRINT_COMPARISON_FAILURE, traceId);
    }
  }
}
