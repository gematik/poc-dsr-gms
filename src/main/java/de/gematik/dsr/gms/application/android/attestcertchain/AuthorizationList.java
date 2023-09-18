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

import static de.gematik.dsr.gms.application.android.attestcertchain.AuthorizationListTag.ATTESTATION_APPLICATION_ID;
import static de.gematik.dsr.gms.application.android.attestcertchain.AuthorizationListTag.ROOT_OF_TRUST;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.*;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class AuthorizationList extends AbstractMap<String, Object> {

  private final Map<AuthorizationListTag, Object> authorizationListTags =
      new EnumMap<>(AuthorizationListTag.class);

  private final int attestationVersion;

  AuthorizationList(ASN1Sequence authorizationListSequence, int attestationVersion) {
    this.attestationVersion = attestationVersion;
    Arrays.stream(authorizationListSequence.toArray())
        .map(ASN1TaggedObject.class::cast)
        .forEach(
            entry -> {
              AuthorizationListTag authorizationListTag =
                  AuthorizationListTag.defineByTagNumber(entry.getTagNo(), attestationVersion);
              ASN1Primitive asn1Primitive = entry.getBaseObject().toASN1Primitive();
              Optional<?> value =
                  authorizationListTag.getType().apply(asn1Primitive, attestationVersion);
              value.ifPresent(t -> authorizationListTags.put(authorizationListTag, t));
            });
  }

  public Optional<RootOfTrust> getRootOfTrust() {
    return Optional.ofNullable((RootOfTrust) authorizationListTags.get(ROOT_OF_TRUST));
  }

  public Optional<AttestationApplicationId> getAttestationApplicationId() {
    return Optional.ofNullable(
        (AttestationApplicationId) authorizationListTags.get(ATTESTATION_APPLICATION_ID));
  }

  @Override
  public Set<Entry<String, Object>> entrySet() {
    Set<Entry<String, Object>> entries = new HashSet<>();
    Set<AuthorizationListTag> filter = Set.of(ROOT_OF_TRUST, ATTESTATION_APPLICATION_ID);
    authorizationListTags.entrySet().stream()
        .filter(e -> !filter.contains(e.getKey()))
        .map(e -> new SimpleEntry<>(e.getKey().getTagKey(), e.getValue()))
        .forEach(entries::add);
    entries.add(new SimpleEntry<>(ROOT_OF_TRUST.getTagKey(), getRootOfTrust()));
    entries.add(
        new SimpleEntry<>(ATTESTATION_APPLICATION_ID.getTagKey(), getAttestationApplicationId()));
    return entries;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    AuthorizationList that = (AuthorizationList) o;
    return attestationVersion == that.attestationVersion
        && Objects.equals(authorizationListTags, that.authorizationListTags);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorizationListTags, attestationVersion);
  }
}
