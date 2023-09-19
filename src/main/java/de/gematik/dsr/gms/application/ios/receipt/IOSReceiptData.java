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

import java.util.Arrays;

/**
 * Data relevant for receipt parsing and validation
 *
 * @param receipt receipt bytes
 * @param deviceKey attested device key fingerprint.
 */
public record IOSReceiptData(byte[] receipt, byte[] deviceKey) {

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    IOSReceiptData that = (IOSReceiptData) o;
    return Arrays.equals(receipt, that.receipt) && Arrays.equals(deviceKey, that.deviceKey);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(receipt);
    result = 31 * result + Arrays.hashCode(deviceKey);
    return result;
  }

  @Override
  public String toString() {
    return "IOSReceiptData{"
        + "receipt="
        + Arrays.toString(receipt)
        + ", deviceKey="
        + Arrays.toString(deviceKey)
        + '}';
  }
}
