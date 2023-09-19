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

package de.gematik.dsr.gms.application.android.attestcertchain;

import static de.gematik.dsr.gms.application.android.attestcertchain.AttestationKeyExceptionReason.UNKNOWN_AUTHORIZATION_LIST_TAG;
import static de.gematik.dsr.gms.application.android.attestcertchain.AuthorizationListTagType.*;

import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.Predicate;

/**
 * Describes the {@link AuthorizationList} single tag entry, where:
 *
 * <ul>
 *   <li>key is the name from the schema
 *   <li>tagNumber is number of the tag from the schema
 *   <li>type is the tag type and mapping to {@link AuthorizationListTagType}
 * </ul>
 *
 * Implements predicate to proof, whether this tag is available for the version
 *
 * <p>https://developer.android.com/training/articles/security-key-attestation#attestation-v200
 * https://source.android.com/docs/security/features/keystore/tags
 */
enum AuthorizationListTag implements Predicate<Integer> {
  PURPOSE("purpose", 1, SET_OF_INTEGER),
  ALGORITHM("algorithm", 2, INTEGER),
  KEY_SIZE("keySize", 3, INTEGER),
  DIGEST("digest", 5, SET_OF_INTEGER),
  PADDING("padding", 6, SET_OF_INTEGER),
  EC_CURVE("ecCurve", 10, INTEGER),
  RSA_PUBLIC_EXPONENT("rsaPublicExponent", 200, INTEGER),
  MG_DIGEST("mgfDigest", 203, SET_OF_INTEGER) {
    @Override
    public boolean test(Integer version) {
      return version == 100 || version == 200;
    }
  },
  ROLLBACK_RESISTANT_NEW("rollbackResistance", 303, BOOLEAN) {
    @Override
    public boolean test(Integer version) {
      return version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  EARLY_BOOT_ONLY("earlyBootOnly", 305, BOOLEAN) {
    @Override
    public boolean test(Integer version) {
      return version == 4 || version == 100 || version == 200;
    }
  },
  ACTIVE_DATE_TIME("activeDateTime", 400, INSTANT),
  ORIGINATION_EXPIRE_DATE_TIME("originationExpireDateTime", 401, INSTANT),
  USAGE_EXPIRE_DATE_TIME("usageExpireDateTime", 402, INSTANT),
  USAGE_COUNT_LIMIT("usageCountLimit", 405, INTEGER) {
    @Override
    public boolean test(Integer version) {
      return version == 100 || version == 200;
    }
  },
  NO_AUTH_REQUIRED("noAuthRequired", 503, BOOLEAN),
  USER_AUTH_TYPE("userAuthType", 504, INTEGER),
  AUTH_TIMEOUT("authTimeout", 505, DURATION),
  ALLOW_WHILE_ON_BODY("allowWhileOnBody", 506, BOOLEAN),
  TRUSTED_USER_PRESENCE_REQUIRED("trustedUserPresenceRequired", 507, BOOLEAN) {
    @Override
    public boolean test(Integer version) {
      return version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  TRUSTED_CONFIRMATION_REQUIRED("trustedConfirmationRequired", 508, BOOLEAN) {
    @Override
    public boolean test(Integer version) {
      return version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  UNLOCKED_DEVICE_REQUIRED("unlockedDeviceRequired", 509, BOOLEAN) {
    @Override
    public boolean test(Integer version) {
      return version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  ALL_APPLICATIONS("allApplications", 600, BOOLEAN) {
    @Override
    public boolean test(Integer version) {
      return version == 1 || version == 2 || version == 3 || version == 4;
    }
  },
  APPLICATION_ID("applicationId", 601, OCTET_STRING) {
    @Override
    public boolean test(Integer version) {
      return version == 1 || version == 2 || version == 3 || version == 4;
    }
  },
  CREATION_DATE_TIME("creationDateTime", 701, INSTANT),
  ORIGIN("origin", 702, INTEGER),
  ROLLBACK_RESISTANT("rollbackResistant", 703, BOOLEAN) {
    @Override
    public boolean test(Integer version) {
      return version == 1 || version == 2;
    }
  },
  ROOT_OF_TRUST("rootOfTrust", 704, AuthorizationListTagType.ROOT_OF_TRUST),
  OS_VERSION("osVersion", 705, INTEGER),
  OS_PATCH_LEVEL("osPatchLevel", 706, INTEGER),
  ATTESTATION_APPLICATION_ID(
      "attestationApplicationId", 709, AuthorizationListTagType.ATTESTATION_APPLICATION_ID) {
    @Override
    public boolean test(Integer version) {
      return version == 2 || version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  ATTESTATION_ID_BRAND("attestationIdBrand", 710, OCTET_STRING) {
    @Override
    public boolean test(Integer version) {
      return version == 2 || version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  ATTESTATION_ID_DEVICE("attestationIdDevice", 711, OCTET_STRING) {
    @Override
    public boolean test(Integer version) {
      return version == 2 || version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  ATTESTATION_ID_PRODUCT("attestationIdProduct", 712, OCTET_STRING) {
    @Override
    public boolean test(Integer version) {
      return version == 2 || version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  ATTESTATION_ID_SERIAL("attestationIdSerial", 713, OCTET_STRING) {
    @Override
    public boolean test(Integer version) {
      return version == 2 || version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  ATTESTATION_ID_IMEI("attestationIdImei", 714, OCTET_STRING) {
    @Override
    public boolean test(Integer version) {
      return version == 2 || version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  ATTESTATION_ID_MEID("attestationIdMeid", 715, OCTET_STRING) {
    @Override
    public boolean test(Integer version) {
      return version == 2 || version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  ATTESTATION_ID_MANUFACTURER("attestationIdManufacturer", 716, OCTET_STRING) {
    @Override
    public boolean test(Integer version) {
      return version == 2 || version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  ATTESTATION_ID_MODEL("attestationIdModel", 717, OCTET_STRING) {
    @Override
    public boolean test(Integer version) {
      return version == 2 || version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  VENDOR_PATCH_LEVEL("vendorPatchLevel", 718, INTEGER) {
    @Override
    public boolean test(Integer version) {
      return version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  BOOT_PATCH_LEVEL("bootPatchLevel", 719, INTEGER) {
    @Override
    public boolean test(Integer version) {
      return version == 3 || version == 4 || version == 100 || version == 200;
    }
  },
  DEVICE_UNIQUE_ATTESTATION("deviceUniqueAttestation", 720, BOOLEAN) {
    @Override
    public boolean test(Integer version) {
      return version == 4 || version == 100 || version == 200;
    }
  };

  private final int tagNumber;

  private final String tagKey;

  private final AuthorizationListTagType type;

  AuthorizationListTag(String tagKey, int tagNumber, AuthorizationListTagType type) {
    this.tagNumber = tagNumber;
    this.tagKey = tagKey;
    this.type = type;
  }

  public int getTagNumber() {
    return tagNumber;
  }

  public String getTagKey() {
    return tagKey;
  }

  public AuthorizationListTagType getType() {
    return type;
  }

  /**
   * Defines whether this tag is available for the given version. Default is true, the concrete tags
   * overrides this method with special version comparison
   *
   * @param version the attestation version of the current list.
   * @return true, if this tag is available in the given version.
   */
  @Override
  public boolean test(Integer version) {
    return version == 1
        || version == 2
        || version == 3
        || version == 4
        || version == 100
        || version == 200;
  }

  static AuthorizationListTag defineByTagNumber(int tagNumber, int version) {
    return Arrays.stream(values())
        .filter(t -> t.tagNumber == tagNumber)
        .findAny()
        .orElseThrow(
            () ->
                new GMServiceRuntimeException(
                    UNKNOWN_AUTHORIZATION_LIST_TAG,
                    UUID.randomUUID(),
                    String.format(
                        UNKNOWN_AUTHORIZATION_LIST_TAG.getDescription(), tagNumber, version)));
  }
}
