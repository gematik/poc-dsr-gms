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

package de.gematik.dsr.gms.application.ios.receipt.validation;

import static de.gematik.dsr.gms.application.ios.IOSValidationReason.INVALID_APPLE_RECEIPT_EXCHANGE;
import static de.gematik.dsr.gms.application.ios.IOSValidationReason.UNEXPECTED_RECEIPT_APP_ID;

import de.gematik.dsr.gms.application.MasterDataRepository;
import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.ios.receipt.*;
import de.gematik.dsr.gms.domain.DeviceReceiptEntityIOS;
import de.gematik.dsr.gms.infrastructure.DeviceReceiptRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.ClientWebApplicationException;

/**
 * This validation performs the receipt exchange asking new apple attestation data based on <a
 * href="https://developer.apple.com/documentation/devicecheck/assessing_fraud_risk?language=objc">this
 * documentation</a>, replaces the old receipt data with new one and updates the entity and makes
 * the verification of the new receipt.
 *
 * <p>The required data for the exchange:
 *
 * <ul>
 *   <li>old receipt data - has to be a body of request
 *   <li>attested device key fingerprint, saved while registration
 * </ul>
 *
 * @see DeviceReceiptEntityIOS
 * @see IOSReceiptValidation
 */
public class IOSReceiptExchangeValidation
    implements Validation<IOSReceiptExchangeData, IOSReceiptExchangeResult> {

  private static final Logger LOG = Logger.getLogger(IOSReceiptExchangeValidation.class);

  private static final Base64.Decoder DECODER = Base64.getDecoder();

  private static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();

  private final AppleReceiptRestClient appleReceiptRestClient;

  private final AppleJwtTokenIssuer appleJwtTokenIssuer;

  private final IOSReceiptValidation receiptValidation;

  private final MasterDataRepository masterDataRepository;

  private final DeviceReceiptRepository deviceReceiptRepository;

  private final Clock clock;

  public IOSReceiptExchangeValidation(
      AppleReceiptRestClient appleReceiptRestClient,
      AppleJwtTokenIssuer appleJwtTokenIssuer,
      IOSReceiptValidation receiptValidation,
      MasterDataRepository masterDataRepository,
      Clock clock,
      DeviceReceiptRepository deviceReceiptRepository) {
    this.appleReceiptRestClient = appleReceiptRestClient;
    this.appleJwtTokenIssuer = appleJwtTokenIssuer;
    this.receiptValidation = receiptValidation;
    this.masterDataRepository = masterDataRepository;
    this.clock = clock;
    this.deviceReceiptRepository = deviceReceiptRepository;
  }

  @Override
  public IOSReceiptExchangeResult evaluate(IOSReceiptExchangeData dataToValidate) {
    DeviceReceiptEntityIOS deviceReceiptEntityIOS = dataToValidate.oldReceiptData();
    byte[] oldReceipt = DECODER.decode(deviceReceiptEntityIOS.getReceipt());
    IOSReceiptData iosReceiptData =
        new IOSReceiptData(oldReceipt, dataToValidate.deviceAttestedKey());
    // Validate the receipt before sending it to Apple. We cannot validate the creation time as we
    // do not know when it should have been issued at latest. Therefore, we use an epoch instant
    // which de facto skips
    // this check. As we also validate the new receipt on return, this should be acceptable. The
    // true parameter
    // makes this skip
    IOSReceipt iosReceipt =
        receiptValidation.evaluate(new IOSReceiptValidationData(iosReceiptData, true));

    if (sanityChecks(iosReceipt)) {
      byte[] newReceipt =
          requestAppleMetric(resolveTeamId(iosReceipt.getAppId()), iosReceiptData.receipt());
      deviceReceiptEntityIOS.setReceipt(ENCODER.encodeToString(newReceipt));
      deviceReceiptRepository.persist(deviceReceiptEntityIOS);
      iosReceipt =
          receiptValidation.evaluate(
              new IOSReceiptValidationData(
                  new IOSReceiptData(newReceipt, dataToValidate.deviceAttestedKey()), false));
    }

    return new IOSReceiptExchangeResult(deviceReceiptEntityIOS, iosReceipt);
  }

  private byte[] requestAppleMetric(String teamId, byte[] oldReceipt) {
    String token = appleJwtTokenIssuer.issueToken(teamId);
    try {
      byte[] receiptBytes = appleReceiptRestClient.getReceipt(token, ENCODER.encode(oldReceipt));
      return Base64.getDecoder().decode(receiptBytes);
    } catch (ClientWebApplicationException e) {
      UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s Response status code from apple while receipt exchanging is not 200: %s",
          traceId, e.getMessage());
      throw new GMServiceRuntimeException(INVALID_APPLE_RECEIPT_EXCHANGE, traceId, e);
    }
  }

  private String resolveTeamId(String appId) {
    return masterDataRepository.getAvailableAppIds().stream()
        .filter(id -> id.buildAppId().equals(appId))
        .findAny()
        .map(MasterDataRepository.AppId::getTeamId)
        .orElseThrow(
            () -> {
              UUID traceId = UUID.randomUUID();
              LOG.errorf(
                  "%s - Unexpected App ID: %s, AppID doesn't match to any known application ID",
                  traceId, appId);
              throw new GMServiceRuntimeException(UNEXPECTED_RECEIPT_APP_ID, traceId);
            });
  }

  private boolean sanityChecks(IOSReceipt receipt) {
    Instant now = Instant.now(clock);
    Boolean notBefore = receipt.getNotBefore().map(now::isAfter).orElse(true);
    boolean notExpired = now.isBefore(receipt.getExpirationTime());
    return notBefore && notExpired;
  }
}
