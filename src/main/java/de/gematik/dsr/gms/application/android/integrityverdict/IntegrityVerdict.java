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

package de.gematik.dsr.gms.application.android.integrityverdict;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.List;
import java.util.function.Consumer;
import org.apache.commons.lang3.StringUtils;

public interface IntegrityVerdict {

  enum AppLicenseVerdict {
    LICENSED,
    UNLICENSED,
    UNEVALUATED
  }

  enum AppIntegrityVerdict {
    PLAY_RECOGNIZED,
    UNRECOGNIZED_VERSION,
    UNEVALUATED
  }

  enum DeviceIntegrityVerdict {
    MEETS_DEVICE_INTEGRITY,
    MEETS_BASIC_INTEGRITY,
    MEETS_STRONG_INTEGRITY,
    MEETS_VIRTUAL_INTEGRITY
  }

  record IntegrityVerdictToken(
      String packageName,
      String integrityToken,
      Consumer<RequestDetails> nonceVerifier,
      boolean validateVerdicts) {}

  record AppIntegrity(
      String appRecognitionVerdict,
      String packageName,
      List<String> certificateSha256Digest,
      long versionCode) {

    @JsonIgnore
    public AppIntegrityVerdict getVerdict() {
      return AppIntegrityVerdict.valueOf(appRecognitionVerdict());
    }

    @JsonIgnore
    public boolean isEmpty() {
      return StringUtils.isAllEmpty(appRecognitionVerdict, packageName)
          && versionCode == 0
          && (certificateSha256Digest == null || certificateSha256Digest.isEmpty());
    }
  }

  record DeviceIntegrity(List<String> deviceRecognitionVerdict) {

    @JsonIgnore
    public List<DeviceIntegrityVerdict> getVerdicts() {
      return deviceRecognitionVerdict().stream().map(DeviceIntegrityVerdict::valueOf).toList();
    }

    @JsonIgnore
    public boolean isEmpty() {
      return deviceRecognitionVerdict == null || deviceRecognitionVerdict.isEmpty();
    }
  }

  record RequestDetails(String requestPackageName, String nonce, long timestampMillis) {
    public boolean isEmpty() {
      return StringUtils.isAllEmpty(requestPackageName, nonce) && timestampMillis == 0;
    }
  }

  record AccountDetails(String appLicensingVerdict) {

    @JsonIgnore
    public AppLicenseVerdict getVerdict() {
      return AppLicenseVerdict.valueOf(appLicensingVerdict());
    }

    @JsonIgnore
    public boolean isEmpty() {
      return StringUtils.isEmpty(appLicensingVerdict);
    }
  }

  record TokenPayloadExternal(
      RequestDetails requestDetails,
      AppIntegrity appIntegrity,
      DeviceIntegrity deviceIntegrity,
      AccountDetails accountDetails) {

    public DeviceHealthIntegrityVerdict getDeviceHealthIntegrityVerdict() {
      return new DeviceHealthIntegrityVerdict(appIntegrity(), deviceIntegrity(), accountDetails());
    }
  }

  record DeviceHealthIntegrityVerdict(
      AppIntegrity appIntegrity, DeviceIntegrity deviceIntegrity, AccountDetails accountDetails) {}
}
