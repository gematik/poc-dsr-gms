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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import de.gematik.dsr.gms.application.model.DeviceType;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(
    use = JsonTypeInfo.Id.NAME,
    property = "type",
    include = JsonTypeInfo.As.EXISTING_PROPERTY)
@JsonSubTypes({
  @JsonSubTypes.Type(value = AndroidRegistrationTokenPayload.class, name = "ANDROID"),
  @JsonSubTypes.Type(value = AndroidRegistrationTokenPayload.class, name = "Android"),
  @JsonSubTypes.Type(value = AndroidRegistrationTokenPayload.class, name = "android"),
  @JsonSubTypes.Type(value = IOSRegistrationTokenPayload.class, name = "IOS"),
  @JsonSubTypes.Type(value = IOSRegistrationTokenPayload.class, name = "ios"),
  @JsonSubTypes.Type(value = IOSRegistrationTokenPayload.class, name = "iOS")
})
public interface RegistrationTokenPayload {

  String iss();

  // base64 SHA256
  String sub();

  Long iat();

  @JsonProperty
  DeviceType type();

  String nonce();

  // base64 DER
  String csr();
}
