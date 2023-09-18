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

package de.gematik.dsr.gms.application.ios.config;

import de.gematik.dsr.gms.application.ios.receipt.validation.AppleJwtTokenIssuer;
import de.gematik.dsr.gms.application.util.SystemClockProvider;
import io.quarkus.arc.profile.UnlessBuildProfile;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Dependent;
import java.security.PrivateKey;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@Dependent
public class AppleAccessConfiguration {

  @ApplicationScoped
  @UnlessBuildProfile("test")
  public AppleJwtTokenIssuer appleJwtTokenIssuer(
      @ConfigProperty(name = "ios.apple-receipt.token.key") PrivateKey privateKey,
      SystemClockProvider systemClockProvider,
      @ConfigProperty(name = "ios.receipt.key-identifier") String keyIdentifier) {
    return new AppleJwtTokenIssuer(privateKey, systemClockProvider, keyIdentifier);
  }
}
