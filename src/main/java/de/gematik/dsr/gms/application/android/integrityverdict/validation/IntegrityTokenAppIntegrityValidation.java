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

package de.gematik.dsr.gms.application.android.integrityverdict.validation;

import static de.gematik.dsr.gms.application.android.integrityverdict.IntegrityVerdict.AppIntegrityVerdict.PLAY_RECOGNIZED;
import static de.gematik.dsr.gms.application.android.integrityverdict.validation.IntegrityTokenAppIntegrityValidation.AppIntegrityValidationReason.*;

import de.gematik.dsr.gms.application.MasterDataRepository;
import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.android.integrityverdict.IntegrityVerdict;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.exception.ServiceExceptionReason;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import org.jboss.logging.Logger;

public class IntegrityTokenAppIntegrityValidation
    implements Validation<IntegrityVerdict.TokenPayloadExternal, IntegrityVerdict.AppIntegrity> {

  private static final Logger LOG = Logger.getLogger(IntegrityTokenAppIntegrityValidation.class);

  private final List<MasterDataRepository.AvailablePackage> availablePackages;
  private final String packageName;

  private final boolean validateVerdict;

  public IntegrityTokenAppIntegrityValidation(
      String packageName,
      List<MasterDataRepository.AvailablePackage> availablePackages,
      boolean validateVerdict) {
    this.packageName = packageName;
    this.availablePackages = availablePackages;
    this.validateVerdict = validateVerdict;
  }

  @Override
  public IntegrityVerdict.AppIntegrity evaluate(
      IntegrityVerdict.TokenPayloadExternal dataToValidate) {
    IntegrityVerdict.AppIntegrity appIntegrity = verifyAppIntegrity(dataToValidate);
    checkAppIntegrity(appIntegrity);
    return appIntegrity;
  }

  private IntegrityVerdict.AppIntegrity verifyAppIntegrity(
      IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal) {
    IntegrityVerdict.AppIntegrity appIntegrity = tokenPayloadExternal.appIntegrity();
    if (appIntegrity == null || appIntegrity.isEmpty()) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf("%s Error getting app integrity from external google token payload.", traceId);
      throw new GMServiceRuntimeException(MISSING_APP_INTEGRITY_VERDICT, UUID.randomUUID());
    }
    return appIntegrity;
  }

  private void checkAppIntegrity(IntegrityVerdict.AppIntegrity appIntegrity) {
    checkAppIntegrityVerdictValue(appIntegrity);
    MasterDataRepository.AvailablePackage availablePackage = checkPackageName(appIntegrity);
    checkCertificateDigest(availablePackage, appIntegrity);
  }

  private MasterDataRepository.AvailablePackage checkPackageName(
      IntegrityVerdict.AppIntegrity appIntegrity) {
    if (!packageName.equals(appIntegrity.packageName())) {
      throw packageMismatchException().get();
    }
    return availablePackages.stream()
        .filter(available -> available.getPackageName().equals(appIntegrity.packageName()))
        .filter(available -> available.getVersion() == appIntegrity.versionCode())
        .findAny()
        .orElseThrow(packageMismatchException());
  }

  private Supplier<GMServiceRuntimeException> packageMismatchException() {
    return () -> {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf("%s The package name does not match available Google Play records.", traceId);
      return new GMServiceRuntimeException(APP_INTEGRITY_PACKAGE_NAME_VIOLATIONS, traceId);
    };
  }

  private void checkCertificateDigest(
      MasterDataRepository.AvailablePackage availablePackage,
      IntegrityVerdict.AppIntegrity appIntegrity) {
    List<String> certificateSha256Digest = appIntegrity.certificateSha256Digest();
    if (certificateSha256Digest == null || certificateSha256Digest.isEmpty()) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf("%s No certificate digests.", traceId);
      throw new GMServiceRuntimeException(MISSING_INTEGRITY_CERTIFICATE_DIGEST, traceId);
    }
    String sha256Digest = availablePackage.getCertificateSha256Digest();
    if (!certificateSha256Digest.contains(sha256Digest)) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf("%s Certificates mismatch.", traceId);
      throw new GMServiceRuntimeException(APP_INTEGRITY_CERTIFICATE_DIGEST_VIOLATIONS, traceId);
    }
  }

  private void checkAppIntegrityVerdictValue(IntegrityVerdict.AppIntegrity appIntegrity) {
    if (!validateVerdict) {
      LOG.infof("Verdict %s is not validated!", appIntegrity.getVerdict());
      return;
    }
    try {
      IntegrityVerdict.AppIntegrityVerdict appIntegrityVerdict = appIntegrity.getVerdict();
      if (!PLAY_RECOGNIZED.equals(appIntegrityVerdict)) {
        throw new GMServiceRuntimeException(APP_INTEGRITY_VERDICT_VIOLATIONS, UUID.randomUUID());
      }
    } catch (IllegalArgumentException e) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s Error parsing app integrity verdict from external google token payload. Cant parse to"
              + " known values: %s",
          traceId, IntegrityVerdict.AppIntegrityVerdict.values());
      throw new GMServiceRuntimeException(UNKNOWN_APP_INTEGRITY_VERDICT, traceId, e);
    }
  }

  enum AppIntegrityValidationReason implements ServiceExceptionReason {
    APP_INTEGRITY_PACKAGE_NAME_VIOLATIONS(
        "Application integrity is violated due to package name mismatch"),

    APP_INTEGRITY_CERTIFICATE_DIGEST_VIOLATIONS(
        "Application integrity is violated due to certificate checksum mismatch"),

    APP_INTEGRITY_VERDICT_VIOLATIONS(
        "Application integrity is violated due to its integrity verdict"),

    MISSING_APP_INTEGRITY_VERDICT("No app integrity value"),

    MISSING_INTEGRITY_CERTIFICATE_DIGEST("No certificate digests are calculated"),

    UNKNOWN_APP_INTEGRITY_VERDICT(
        "Not parsable or unknown app integrity value. Possible values are: "
            + IntegrityVerdict.AppIntegrityVerdict.values());

    private final String description;

    AppIntegrityValidationReason(String description) {
      this.description = description;
    }

    @Override
    public String getDescription() {
      return description;
    }

    @Override
    public Response.Status getStatus() {
      return Response.Status.BAD_REQUEST;
    }
  }
}
