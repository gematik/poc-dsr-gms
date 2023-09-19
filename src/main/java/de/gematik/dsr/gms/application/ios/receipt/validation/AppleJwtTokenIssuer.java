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

package de.gematik.dsr.gms.application.ios.receipt.validation;

import de.gematik.dsr.gms.application.util.SystemClockProvider;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.Jwt;
import java.security.PrivateKey;

/**
 * Builds the access token to request the attestation data from the apple services.
 *
 * <p>The data the token has to contain:
 *
 * <ul>
 *   <li>algorithm - constant value - ES256
 *   <li>to build the access token - teamId the company uses for developing apps
 *   <li>The 10-character Key ID - keyIdentifier of the company developer account
 *   <li>"issued at" time
 * </ul>
 *
 * <a
 * href="https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/establishing_a_token-based_connection_to_apns?language=objc">
 * Establishing a token-based connection to APNs </a>
 */
public class AppleJwtTokenIssuer {

  private final PrivateKey privateKey;

  private final SystemClockProvider systemClockProvider;

  private final String keyIdentifier;

  public AppleJwtTokenIssuer(
      PrivateKey privateKey, SystemClockProvider systemClockProvider, String keyIdentifier) {
    this.privateKey = privateKey;
    this.systemClockProvider = systemClockProvider;
    this.keyIdentifier = keyIdentifier;
  }

  public String issueToken(String teamIdentifier) {
    return Jwt.claims()
        .issuer(teamIdentifier)
        .issuedAt(systemClockProvider.systemClock().instant())
        .jws()
        .keyId(keyIdentifier)
        .algorithm(SignatureAlgorithm.ES256)
        .sign(privateKey);
  }
}
