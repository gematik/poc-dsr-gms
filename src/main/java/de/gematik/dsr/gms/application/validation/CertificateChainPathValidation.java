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

package de.gematik.dsr.gms.application.validation;

import static de.gematik.dsr.gms.application.Validation.ValidationExceptionReason.*;

import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.time.Clock;
import java.util.*;
import java.util.stream.Collectors;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.jboss.logging.Logger;

/**
 * Validates certificate chain path. Inspired by
 * http://www.java2s.com/example/java/security/validate-a-certificate-chain.html
 */
public class CertificateChainPathValidation
    implements Validation<List<X509Certificate>, List<X509Certificate>> {

  private static final Logger LOG = Logger.getLogger(CertificateChainPathValidation.class);

  private final List<X509Certificate> rootCertificates;

  private final Clock clock;

  public CertificateChainPathValidation(List<X509Certificate> rootCertificates, Clock clock) {
    this.rootCertificates = rootCertificates;
    this.clock = clock;
  }

  @Override
  public List<X509Certificate> evaluate(List<X509Certificate> dataToValidate) {
    try {
      PKIXCertPathValidatorResult pkixCertPathValidatorResult =
          validatePath(dataToValidate, getRootCAs());
      if (pkixCertPathValidatorResult != null) {
        LOG.infof("Successfully validated certificate chain path.");
      }
      return dataToValidate;
    } catch (GeneralSecurityException | IOException e) {
      UUID traceId = UUID.randomUUID();
      LOG.errorf("%s - Error while certificate chain path validation", traceId);
      throw new GMServiceRuntimeException(INVALID_CERTIFICATE_CHAIN_PATH, traceId, e);
    }
  }

  /** Validate a certificate chain. Normal return indicates a successful validation. */
  protected PKIXCertPathValidatorResult validatePath(
      List<X509Certificate> certs, Set<TrustAnchor> trustAnchors) throws GeneralSecurityException {
    CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
    PKIXParameters params = new PKIXParameters(trustAnchors);
    params.setRevocationEnabled(false);
    params.setDate(new Date(clock.millis()));

    CertificateFactory cf = CertificateFactory.getInstance("X509");
    CertPath path = cf.generateCertPath(certs);

    return (PKIXCertPathValidatorResult) cpv.validate(path, params);
  }

  /** Obtains the list of root CAs initialized in the key store. */
  protected Set<TrustAnchor> getRootCAs()
      throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
    X509TrustManager x509tm = getX509TrustManager();

    return Arrays.stream(x509tm.getAcceptedIssuers())
        .map(c -> new TrustAnchor(c, null))
        .collect(Collectors.toSet());
  }

  /** Loads the system default {@link X509TrustManager}. */
  protected X509TrustManager getX509TrustManager()
      throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
    TrustManagerFactory tmf =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    KeyStore keyStore = initializeRootCAsKeyStore();
    tmf.init(keyStore);

    return Arrays.stream(tmf.getTrustManagers())
        .filter(X509TrustManager.class::isInstance)
        .map(X509TrustManager.class::cast)
        .findAny()
        .orElseThrow(
            () -> new GMServiceRuntimeException(MISSING_X509_TRUST_MANAGER, UUID.randomUUID()));
  }

  private KeyStore initializeRootCAsKeyStore()
      throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {
    KeyStore keyStore = KeyStore.getInstance("pkcs12");
    keyStore.load(null);

    for (X509Certificate certificate : rootCertificates) {
      keyStore.setCertificateEntry(certificate.getSerialNumber().toString(16), certificate);
    }
    return keyStore;
  }
}
