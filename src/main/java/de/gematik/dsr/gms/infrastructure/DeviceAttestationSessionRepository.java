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

package de.gematik.dsr.gms.infrastructure;

import de.gematik.dsr.gms.domain.DeviceAttestationSessionEntity;
import de.gematik.dsr.gms.domain.DeviceAttestationSessionKey;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import io.quarkus.panache.common.Parameters;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Optional;

@ApplicationScoped
public class DeviceAttestationSessionRepository
    implements PanacheRepositoryBase<DeviceAttestationSessionEntity, DeviceAttestationSessionKey> {

  public Optional<DeviceAttestationSessionEntity> findByAuthCodeAndCodeChallenge(
      final String authCode, final String codeChallenge) {
    return stream(
            "id.authorisationCode = :authorisationCode AND id.codeChallenge = :codeChallenge",
            Parameters.with("authorisationCode", authCode).and("codeChallenge", codeChallenge))
        .findFirst();
  }
}
