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

package de.gematik.dsr.gms.application.ios.receipt;

import de.gematik.dsr.gms.domain.DeviceReceiptEntityIOS;
import java.util.Arrays;
import java.util.Objects;

/**
 * Data needed for receipt exchange and validation of the new receipt data.
 *
 * @param oldReceiptData entity with the old receipt data.
 * @param deviceAttestedKey attested device key fingerprint.
 */
public record IOSReceiptExchangeData(
    DeviceReceiptEntityIOS oldReceiptData, byte[] deviceAttestedKey) {

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    IOSReceiptExchangeData that = (IOSReceiptExchangeData) o;
    return Objects.equals(oldReceiptData, that.oldReceiptData)
        && Arrays.equals(deviceAttestedKey, that.deviceAttestedKey);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(oldReceiptData);
    result = 31 * result + Arrays.hashCode(deviceAttestedKey);
    return result;
  }

  @Override
  public String toString() {
    return "IOSReceiptExchangeData{"
        + "oldReceiptData="
        + oldReceiptData
        + ", deviceAttestedKey="
        + Arrays.toString(deviceAttestedKey)
        + '}';
  }
}
