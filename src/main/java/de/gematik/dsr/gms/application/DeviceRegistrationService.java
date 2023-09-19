/*
 * Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.dsr.gms.application;

import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.domain.DeviceIdentificationKey;
import de.gematik.dsr.gms.domain.DeviceRegistrationEntity;
import de.gematik.dsr.gms.infrastructure.DeviceRegistrationRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.util.List;

@ApplicationScoped
public class DeviceRegistrationService {

  @Inject DeviceRegistrationRepository repository;

  public List<DeviceRegistrationEntity> getDeviceRegistrationsByUser(final String userIdentifier) {
    return repository.findAllByUserIdentifier(userIdentifier);
  }

  @Transactional
  public void deleteDeviceRegistration(final String userIdentifier, final String deviceIdentifier) {
    boolean deleted =
        repository.deleteById(new DeviceIdentificationKey(userIdentifier, deviceIdentifier));
    if (!deleted) {
      throw new GMServiceRuntimeException(GMServiceExceptionReason.DEVICE_REGISTRATION_NOT_FOUND);
    }
  }
}
