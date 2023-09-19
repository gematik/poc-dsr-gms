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

package de.gematik.dsr.gms.application.ios;

import static de.gematik.dsr.gms.application.ios.IOSValidationReason.DEVICE_RECEIPT_NOT_FOUND;

import de.gematik.dsr.gms.application.DeviceAttestation;
import de.gematik.dsr.gms.application.MasterDataRepository;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.ios.assertion.IOSAssertionResult;
import de.gematik.dsr.gms.application.ios.assertion.IOSAssertionValidation;
import de.gematik.dsr.gms.application.ios.attestation.IOSAttestationResult;
import de.gematik.dsr.gms.application.ios.attestation.IOSAttestationValidation;
import de.gematik.dsr.gms.application.ios.receipt.*;
import de.gematik.dsr.gms.application.ios.receipt.validation.AppleJwtTokenIssuer;
import de.gematik.dsr.gms.application.ios.receipt.validation.AppleReceiptRestClient;
import de.gematik.dsr.gms.application.ios.receipt.validation.IOSReceiptExchangeValidation;
import de.gematik.dsr.gms.application.ios.receipt.validation.IOSReceiptValidation;
import de.gematik.dsr.gms.application.model.DeviceAttestationResult;
import de.gematik.dsr.gms.application.model.DeviceType;
import de.gematik.dsr.gms.application.model.attestation.AttestationTokenPayload;
import de.gematik.dsr.gms.application.model.attestation.IOSAttestationTokenPayload;
import de.gematik.dsr.gms.application.model.registration.IOSRegistrationTokenPayload;
import de.gematik.dsr.gms.application.model.registration.RegistrationTokenPayload;
import de.gematik.dsr.gms.application.util.SystemClockProvider;
import de.gematik.dsr.gms.domain.DeviceReceiptEntityIOS;
import de.gematik.dsr.gms.infrastructure.DeviceReceiptRepository;
import de.gematik.dsr.gms.infrastructure.DeviceRegistrationRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.function.Function;
import java.util.function.Predicate;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.logging.Logger;

@ApplicationScoped
public class IOSDeviceAttestation implements DeviceAttestation {

  private static final Logger LOG = Logger.getLogger(IOSDeviceAttestation.class);

  private static final Function<String, byte[]> DECODING = Base64.getDecoder()::decode;

  @ConfigProperty(name = "ios.attestation-root-certificate-path")
  X509Certificate attestationRootCertificate;

  @ConfigProperty(name = "ios.public-root-certificate-path")
  X509Certificate publicRootCertificate;

  @ConfigProperty(name = "ios.receipt.max-age", defaultValue = "5")
  long receiptMageAge;

  @ConfigProperty(name = "ios.receipt.exchange-enabled", defaultValue = "false")
  boolean exchangeEnabled;

  @Inject SystemClockProvider systemClockProvider;
  @Inject MasterDataRepository masterDataRepository;
  @Inject DeviceRegistrationRepository deviceRegistrationRepository;
  @Inject DeviceReceiptRepository deviceReceiptRepository;
  @RestClient AppleReceiptRestClient appleReceiptRestClient;
  @Inject AppleJwtTokenIssuer appleJwtTokenIssuer;

  @Override
  public DeviceType getType() {
    return DeviceType.IOS;
  }

  @Override
  public DeviceAttestationResult<RegistrationTokenPayload> registration(
      RegistrationTokenPayload body) {
    IOSRegistrationTokenPayload payload = (IOSRegistrationTokenPayload) body;
    IOSAttestationResult iosAttestationResult =
        getIosAttestationValidation()
            .evaluate(
                new IOSValidationData(
                    payload.nonce(),
                    payload.sub(),
                    payload.attestation(),
                    keyIdentifierPredicate(payload.keyId())));

    IOSReceiptData iosReceiptData =
        new IOSReceiptData(
            iosAttestationResult.receipt(), iosAttestationResult.deviceKeyFingerprint());
    IOSReceipt iosReceipt =
        getReceiptValidation().evaluate(new IOSReceiptValidationData(iosReceiptData, false));
    return new IOSDeviceRegistrationResult(payload, iosAttestationResult, iosReceipt);
  }

  private Predicate<byte[]> keyIdentifierPredicate(final String keyId) {
    return bytes ->
        keyId != null && MessageDigest.isEqual(bytes, Base64.getDecoder().decode(keyId));
  }

  @Override
  @Transactional
  public DeviceAttestationResult<AttestationTokenPayload> attestation(
      AttestationTokenPayload body) {
    final IOSAttestationTokenPayload payload = (IOSAttestationTokenPayload) body;
    DeviceReceiptEntityIOS receiptEntityIOS = getOldReceiptData(payload.sub());
    IOSAssertionResult iosAssertionResult =
        getIosAssertionValidation(receiptEntityIOS.getCounter())
            .evaluate(
                new IOSValidationData(
                    payload.nonce(), payload.sub(), payload.assertion(), bytes -> true));

    receiptEntityIOS.setCounter(iosAssertionResult.authenticatorData().getCounter());
    deviceReceiptRepository.persist(receiptEntityIOS);
    Optional<IOSReceipt> iosReceipt = exchangeReceipt(receiptEntityIOS, iosAssertionResult);
    deviceReceiptRepository.flush();
    return new IOSDeviceAttestationResult(payload, iosAssertionResult, iosReceipt);
  }

  private Optional<IOSReceipt> exchangeReceipt(
      final DeviceReceiptEntityIOS receiptEntityIOS, final IOSAssertionResult iosAssertionResult) {
    if (!exchangeEnabled) {
      LOG.info("No apple exchange validation is activated. Assessing fraud risk is not executed.");
      return Optional.empty();
    }
    IOSReceiptExchangeResult exchangeResult =
        getIosReceiptExchangeValidation()
            .evaluate(
                new IOSReceiptExchangeData(
                    receiptEntityIOS, iosAssertionResult.attestedDeviceKey()));
    return Optional.of(exchangeResult.receipt());
  }

  private DeviceReceiptEntityIOS getOldReceiptData(String deviceIdentifier) {
    return deviceReceiptRepository
        .findByDeviceIdentifier(deviceIdentifier)
        .orElseThrow(
            () -> {
              UUID traceId = UUID.randomUUID();
              LOG.errorf("%s No device receipt found by %s", traceId, deviceIdentifier);
              throw new GMServiceRuntimeException(DEVICE_RECEIPT_NOT_FOUND, traceId);
            });
  }

  private IOSReceiptValidation getReceiptValidation() {
    return new IOSReceiptValidation(
        publicRootCertificate,
        Duration.ofMinutes(receiptMageAge),
        systemClockProvider.systemClock(),
        masterDataRepository);
  }

  private IOSReceiptExchangeValidation getIosReceiptExchangeValidation() {
    return new IOSReceiptExchangeValidation(
        appleReceiptRestClient,
        appleJwtTokenIssuer,
        getReceiptValidation(),
        masterDataRepository,
        systemClockProvider.systemClock(),
        deviceReceiptRepository);
  }

  private IOSAttestationValidation getIosAttestationValidation() {
    return new IOSAttestationValidation(
        attestationRootCertificate,
        DECODING,
        systemClockProvider.systemClock(),
        masterDataRepository);
  }

  private IOSAssertionValidation getIosAssertionValidation(long counter) {
    return new IOSAssertionValidation(
        DECODING, masterDataRepository, deviceRegistrationRepository, c -> c >= counter);
  }

  public record IOSDeviceRegistrationResult(
      IOSRegistrationTokenPayload payload,
      IOSAttestationResult attestationResult,
      IOSReceipt receipt)
      implements DeviceAttestationResult<RegistrationTokenPayload> {
    @Override
    public IOSRegistrationTokenPayload getOriginalPayload() {
      return payload;
    }

    @Override
    public Map<String, Object> deviceHealthMap() {
      return Collections.emptyMap();
    }
  }

  record IOSDeviceAttestationResult(
      IOSAttestationTokenPayload payload,
      IOSAssertionResult iosAssertionResult,
      Optional<IOSReceipt> iosReceipt)
      implements DeviceAttestationResult<AttestationTokenPayload> {

    private static final String DEVICE_HEALTH_ASSERTION_KEY = "assertion";

    @Override
    public IOSAttestationTokenPayload getOriginalPayload() {
      return payload;
    }

    @Override
    public Map<String, Object> deviceHealthMap() {
      Map<String, Object> deviceHealth = new HashMap<>();

      deviceHealth.put(DEVICE_HEALTH_ASSERTION_KEY, createAssertion());
      deviceHealth.put(
          DEVICE_HEALTH_DEVICE_ATTRIBUTES_KEY, getOriginalPayload().deviceAttributes());

      return deviceHealth;
    }

    private Map<String, Object> createAssertion() {
      Map<String, Object> assertion = new HashMap<>();

      AuthenticatorData authenticatorData = iosAssertionResult().authenticatorData();

      Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
      assertion.put(
          AuthenticatorData.AuthenticatorDataTag.RP_ID.getDeviceHealthKey(),
          encoder.encodeToString(authenticatorData.getRpId()));
      assertion.put(
          AuthenticatorData.AuthenticatorDataTag.COUNTER.getDeviceHealthKey(),
          authenticatorData.getCounter());
      assertion.put(
          IOSReceiptAttribute.RISK_METRIC.getDeviceHealthKey(),
          iosReceipt()
              .map(IOSReceipt::getRiskMetric)
              .filter(Optional::isPresent)
              .map(Optional::get)
              .map(String::valueOf)
              .orElse("unavailable"));
      return assertion;
    }
  }
}
