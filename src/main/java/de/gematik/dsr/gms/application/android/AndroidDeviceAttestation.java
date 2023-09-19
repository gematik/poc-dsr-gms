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

package de.gematik.dsr.gms.application.android;

import de.gematik.dsr.gms.application.DeviceAttestation;
import de.gematik.dsr.gms.application.android.attestcertchain.AttestationResult;
import de.gematik.dsr.gms.application.android.attestcertchain.validation.AttestCertChainValidation;
import de.gematik.dsr.gms.application.android.integrityverdict.IntegrityVerdict;
import de.gematik.dsr.gms.application.android.integrityverdict.validation.IntegrityVerdictValidation;
import de.gematik.dsr.gms.application.model.DeviceAttestationResult;
import de.gematik.dsr.gms.application.model.DeviceType;
import de.gematik.dsr.gms.application.model.attestation.AndroidAttestationTokenPayload;
import de.gematik.dsr.gms.application.model.attestation.AttestationTokenPayload;
import de.gematik.dsr.gms.application.model.registration.AndroidRegistrationTokenPayload;
import de.gematik.dsr.gms.application.model.registration.RegistrationTokenPayload;
import de.gematik.dsr.gms.application.validation.FingerprintComparison;
import de.gematik.dsr.gms.application.validation.NonceVerifier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

@ApplicationScoped
public class AndroidDeviceAttestation implements DeviceAttestation {

  private static final Logger LOG = Logger.getLogger(AndroidDeviceAttestation.class);

  @ConfigProperty(name = "registration.android.integrity-verdict.on", defaultValue = "true")
  boolean registrationVerdictValidation;

  @Inject AttestCertChainValidation attestCertChainValidation;

  @Inject IntegrityVerdictValidation integrityVerdictValidation;

  @Override
  public DeviceType getType() {
    return DeviceType.ANDROID;
  }

  @Override
  public DeviceAttestationResult<RegistrationTokenPayload> registration(
      RegistrationTokenPayload body) {
    if (!registrationVerdictValidation) {
      LOG.warnf(
          "The verdicts validation by integrity token is turned off! This is only for TEST and is"
              + " an error in production.");
    }
    final AndroidRegistrationTokenPayload payload = (AndroidRegistrationTokenPayload) body;
    final AttestationResult attestationResult =
        attestCertChainValidation.evaluate(
            new AttestCertChainValidation.AttestCertChainData(
                payload.attestCertChain(),
                bytes -> NonceVerifier.verifyKeypairMTLSNonce(payload.nonce(), bytes),
                bytes -> FingerprintComparison.compare(bytes, payload.sub()),
                registrationVerdictValidation));

    IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal =
        integrityVerdictValidation.evaluate(
            new IntegrityVerdict.IntegrityVerdictToken(
                payload.packageName(),
                payload.integrityVerdict(),
                requestDetails ->
                    NonceVerifier.verifyIntegrityNonce(payload.nonce(), requestDetails.nonce()),
                registrationVerdictValidation));

    return new AndroidDeviceRegistrationResult(payload, attestationResult, tokenPayloadExternal);
  }

  @Override
  public DeviceAttestationResult<AttestationTokenPayload> attestation(
      AttestationTokenPayload body) {

    AndroidAttestationTokenPayload payload = (AndroidAttestationTokenPayload) body;
    final AttestationResult attestationResult =
        attestCertChainValidation.evaluate(
            new AttestCertChainValidation.AttestCertChainData(
                payload.attestCertChain(),
                bytes -> NonceVerifier.verifyAttestDerivedNonce(payload.nonce(), bytes),
                bytes -> {}, // TODO: TBD - specification is not clear (DSRGMS-45)
                false));

    IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal =
        integrityVerdictValidation.evaluate(
            new IntegrityVerdict.IntegrityVerdictToken(
                payload.packageName(),
                payload.integrityVerdict(),
                requestDetails ->
                    NonceVerifier.verifyPlayIntegrityNonce(payload.nonce(), requestDetails.nonce()),
                false));
    return new AndroidDeviceAttestationResult(payload, attestationResult, tokenPayloadExternal);
  }

  public record AndroidDeviceAttestationResult(
      AndroidAttestationTokenPayload payload,
      AttestationResult attestationResult,
      IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal)
      implements DeviceAttestationResult<AttestationTokenPayload> {

    private static final String DEVICE_HEALTH_INTEGRITY_VERDICT_KEY = "integrityVerdict";
    private static final String DEVICE_HEALTH_KEY_ID_ATTESTATION_KEY = "keyIdAttestation";

    @Override
    public AndroidAttestationTokenPayload getOriginalPayload() {
      return payload;
    }

    @Override
    public Map<String, Object> deviceHealthMap() {
      Map<String, Object> deviceHealth = new HashMap<>();

      deviceHealth.put(
          DEVICE_HEALTH_INTEGRITY_VERDICT_KEY,
          tokenPayloadExternal().getDeviceHealthIntegrityVerdict());
      deviceHealth.put(
          DEVICE_HEALTH_KEY_ID_ATTESTATION_KEY, attestationResult().attestationKeyDescription());
      deviceHealth.put(
          DEVICE_HEALTH_DEVICE_ATTRIBUTES_KEY, getOriginalPayload().deviceAttributes());

      return deviceHealth;
    }
  }

  public record AndroidDeviceRegistrationResult(
      AndroidRegistrationTokenPayload payload,
      AttestationResult attestationResult,
      IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal)
      implements DeviceAttestationResult<RegistrationTokenPayload> {

    @Override
    public AndroidRegistrationTokenPayload getOriginalPayload() {
      return payload;
    }

    @Override
    public Map<String, Object> deviceHealthMap() {
      return Collections.emptyMap();
    }
  }
}
