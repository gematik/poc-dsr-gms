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

package de.gematik.dsr.gms.application.model.registration;

import de.gematik.dsr.gms.application.model.DeviceType;
import java.util.List;

public record AndroidRegistrationTokenPayload(
    String iss,
    String sub,
    Long iat,
    String nonce,
    String csr,
    List<String> attestCertChain,
    String integrityVerdict,
    String packageName)
    implements RegistrationTokenPayload {

  @Override
  public DeviceType type() {
    return DeviceType.ANDROID;
  }
}
