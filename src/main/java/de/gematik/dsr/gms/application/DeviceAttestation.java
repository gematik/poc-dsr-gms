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

package de.gematik.dsr.gms.application;

import de.gematik.dsr.gms.application.model.DeviceAttestationResult;
import de.gematik.dsr.gms.application.model.DeviceType;
import de.gematik.dsr.gms.application.model.attestation.AttestationTokenPayload;
import de.gematik.dsr.gms.application.model.registration.RegistrationTokenPayload;

/** Validates the data from token payload, received from the device */
public interface DeviceAttestation {

  /**
   * Returns the type, this attestation is for
   *
   * @return type of the device, the given attestation is suitable for.
   */
  DeviceType getType();

  /**
   * Implements the attestation of device while registration process
   *
   * @param body payload of the device registration token
   * @return the result of the attestation according to the device type.
   * @throws de.gematik.dsr.gms.application.exception.GMServiceRuntimeException occurs, if any for
   *     the registration flow specified verification steps fails
   */
  DeviceAttestationResult<RegistrationTokenPayload> registration(RegistrationTokenPayload body);

  /**
   * Implements the attestation of device while attestation: accessing to any of protected services
   *
   * @param body payload of the device attestation token
   * @return the result of the attestation according to the device type.
   * @throws de.gematik.dsr.gms.application.exception.GMServiceRuntimeException occurs, if any for
   *     the attestation flow specified verification steps fails
   */
  DeviceAttestationResult<AttestationTokenPayload> attestation(AttestationTokenPayload body);
}
