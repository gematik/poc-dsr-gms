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
@Table(name = "device_registration")
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name = "device_type", length = 50)
public abstract class DeviceRegistrationEntity {

  @EmbeddedId private DeviceIdentificationKey id;

  @Column(name = "device_type", insertable = false, updatable = false)
  private String deviceType;

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

  public DeviceIdentificationKey getId() {
    return id;
  }

  protected void setId(DeviceIdentificationKey id) {
    this.id = id;
  }

  public String getDeviceType() {
    return deviceType;
  }

  public OffsetDateTime getCreationTimestamp() {
    return creationTimestamp;
  }

  public OffsetDateTime getUpdateTimestamp() {
    return updateTimestamp;
  }
}
