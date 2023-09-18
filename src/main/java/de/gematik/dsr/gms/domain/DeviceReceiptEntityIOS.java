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

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "device_receipt")
public class DeviceReceiptEntityIOS {

  @EmbeddedId private DeviceIdentificationKey id;

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

  /**
   * Base64 encoded String of the last receipt either extracted from attestation while registration
   * or saved after the last access to apple appattest (https://data.appattest.apple.com) or
   * (https://data-development.appattest.apple.com)
   */
  @Column(name = "receipt", columnDefinition = "TEXT")
  private String receipt;

  @Column(name = "counter", columnDefinition = "BIGINT")
  private long counter;

  protected DeviceReceiptEntityIOS() {}

  public DeviceReceiptEntityIOS(DeviceIdentificationKey id, String receipt, long counter) {
    this.id = id;
    this.receipt = receipt;
    this.counter = counter;
  }

  public DeviceIdentificationKey getId() {
    return id;
  }

  public OffsetDateTime getCreationTimestamp() {
    return creationTimestamp;
  }

  public OffsetDateTime getUpdateTimestamp() {
    return updateTimestamp;
  }

  public String getReceipt() {
    return receipt;
  }

  public long getCounter() {
    return counter;
  }

  public void setReceipt(String receipt) {
    this.receipt = receipt;
  }

  public void setCounter(long counter) {
    this.counter = counter;
  }
}
