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

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;
import org.bouncycastle.asn1.*;

/**
 * Describes types of {@link AuthorizationList} tags und provides decoding function for
 * corresponding type, which converts the {@link ASN1Primitive} to the defined java type according
 * to the attestation version schema and wraps it into an {@link Optional}.
 */
enum AuthorizationListTagType implements BiFunction<ASN1Primitive, Integer, Optional<?>> {
  INTEGER(
      (p, v) ->
          Optional.ofNullable(p).map(ASN1Integer.class::cast).map(ASN1Integer::intValueExact)),

  SET_OF_INTEGER(
      (p, v) -> {
        Optional<ASN1Set> asn1Encodables = Optional.ofNullable(p).map(ASN1Set.class::cast);
        if (asn1Encodables.isEmpty()) {
          return Optional.empty();
        }
        ASN1Set asn1Set = asn1Encodables.get();
        final Set<Integer> integers = new HashSet<>(asn1Set.size());
        for (ASN1Encodable asn1Encodable : asn1Set) {
          integers.add(((ASN1Integer) asn1Encodable).intValueExact());
        }

        return Optional.of(integers);
      }),

  BOOLEAN((p, v) -> Optional.of(p != null)),

  DURATION(
      (p, v) ->
          Optional.ofNullable(p)
              .map(ASN1Integer.class::cast)
              .map(ASN1Integer::intValueExact)
              .map(Duration::ofSeconds)),

  INSTANT(
      (p, v) ->
          Optional.ofNullable(p)
              .map(ASN1Integer.class::cast)
              .map(ASN1Integer::longValueExact)
              .map(Instant::ofEpochMilli)),

  OCTET_STRING(
      (p, v) ->
          Optional.ofNullable(p).map(ASN1OctetString.class::cast).map(ASN1OctetString::getOctets)),

  ROOT_OF_TRUST(
      (p, v) ->
          Optional.ofNullable(p).map(ASN1Sequence.class::cast).map(seq -> new RootOfTrust(seq, v))),

  ATTESTATION_APPLICATION_ID(
      (p, v) ->
          OCTET_STRING
              .parseFunction
              .apply(p, v)
              .map(s -> (byte[]) s)
              .map(AttestationApplicationId::new));

  private final BiFunction<ASN1Primitive, Integer, Optional<?>> parseFunction;

  AuthorizationListTagType(BiFunction<ASN1Primitive, Integer, Optional<?>> parseFunction) {
    this.parseFunction = parseFunction;
  }

  @Override
  public Optional<?> apply(ASN1Primitive asn1Primitive, Integer version) {
    return parseFunction.apply(asn1Primitive, version);
  }
}
