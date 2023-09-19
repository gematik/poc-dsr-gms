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

package de.gematik.dsr.gms.domain;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "device_attestation_session")
public class DeviceAttestationSessionEntity {

  @EmbeddedId private DeviceAttestationSessionKey id;

  @Column(name = "user_id", nullable = false)
  private String userIdentifier;

  @Column(name = "attestation_token", nullable = false, columnDefinition = "TEXT")
  private String attestationToken;

  @Column(name = "device_token", columnDefinition = "TEXT")
  private String deviceToken;

  @CreationTimestamp
  @Column(
      name = "creation_timestamp",
      nullable = false,
      columnDefinition = "TIMESTAMP WITH TIME ZONE")
  private OffsetDateTime creationTimestamp;

  @UpdateTimestamp
  @Column(
      name = "update_timestamp",
      nullable = false,
      columnDefinition = "TIMESTAMP WITH TIME ZONE")
  private OffsetDateTime updateTimestamp;

  @Column(name = "expiry_timestamp", columnDefinition = "TIMESTAMP WITH TIME ZONE")
  private OffsetDateTime expiryTimestamp;

  protected DeviceAttestationSessionEntity() {
    super();
  }

  public DeviceAttestationSessionEntity(
      final DeviceAttestationSessionKey id,
      final String userIdentifier,
      final String attestationToken) {
    this.setId(id);
    this.userIdentifier = userIdentifier;
    this.attestationToken = attestationToken;
  }

  public DeviceAttestationSessionKey getId() {
    return id;
  }

  protected void setId(DeviceAttestationSessionKey id) {
    this.id = id;
  }

  public String getUserIdentifier() {
    return userIdentifier;
  }

  public String getAttestationToken() {
    return attestationToken;
  }

  public String getDeviceToken() {
    return deviceToken;
  }

  public void setDeviceToken(
      final String deviceToken, final OffsetDateTime sessionExpiryTimestamp) {
    this.deviceToken = deviceToken;
    this.expiryTimestamp = sessionExpiryTimestamp;
  }

  public OffsetDateTime getCreationTimestamp() {
    return creationTimestamp;
  }

  public OffsetDateTime getUpdateTimestamp() {
    return updateTimestamp;
  }

  public OffsetDateTime getExpiryTimestamp() {
    return expiryTimestamp;
  }
}
