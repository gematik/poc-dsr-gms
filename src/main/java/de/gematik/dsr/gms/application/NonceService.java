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

package de.gematik.dsr.gms.application;

import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.domain.NonceEntity;
import de.gematik.dsr.gms.infrastructure.NonceRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

@ApplicationScoped
public class NonceService {

  private static final Logger LOG = Logger.getLogger(NonceService.class);

  @Inject NonceRepository repository;

  @ConfigProperty(name = "nonce.bytes", defaultValue = "64") // "number of bytes"
  int numberOfBytes;

  @ConfigProperty(name = "nonce.validity", defaultValue = "60") // "validity in minutes"
  int validity;

  @Transactional
  public String generateNonce() {
    final var nonce = NonceGenerator.getNonceAsBase64EncodedString(numberOfBytes);
    final var nonceEntity = new NonceEntity(nonce, OffsetDateTime.now().plusMinutes(validity));
    repository.persistAndFlush(nonceEntity);
    return nonce;
  }

  public void verifyNonce(final String nonce) {
    if (Objects.isNull(nonce)) {
      final UUID traceId = UUID.randomUUID();
      LOG.infof("%s Invalid device registration token, nonce is null", traceId);
      throw new GMServiceRuntimeException(GMServiceExceptionReason.INVALID_TOKEN_SYNTAX, traceId);
    }

    final var nonceEntity = repository.findById(nonce);
    if (Objects.isNull(nonceEntity)) {
      final UUID traceId = UUID.randomUUID();
      LOG.infof("%s Nonce %s not found.", traceId, nonce);
      throw new GMServiceRuntimeException(GMServiceExceptionReason.NONCE_INVALID, traceId);
    }

    // delete nonce after reading
    repository.deleteById(nonce);
    repository.flush();

    if (nonceEntity.getExpiryTimestamp().isBefore(OffsetDateTime.now())) {
      final UUID traceId = UUID.randomUUID();
      LOG.infof("%s Nonce %s already expired.", traceId, nonce);
      throw new GMServiceRuntimeException(GMServiceExceptionReason.NONCE_EXPIRED, traceId);
    }
  }
}
