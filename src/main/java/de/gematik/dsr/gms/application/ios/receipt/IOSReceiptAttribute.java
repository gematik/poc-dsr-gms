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

package de.gematik.dsr.gms.application.ios.receipt;

import static de.gematik.dsr.gms.application.ios.IOSValidationReason.UNREADABLE_RECEIPT;

import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.idp.crypto.CryptoLoader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.ToIntFunction;
import org.jboss.logging.Logger;

/**
 * This enum describes the single App Attest receipt payload field according to the table:
 *
 * <table>
 *     <tr><th>Field</th><th>Value</th><th>Example</th></tr>
 *     <tr><td>2</td><td>App ID</td><td>A1B2C3D4E5.com.example.appname</td></tr>
 *     <tr><td>3</td><td>Attested Public Key</td><td>...</td></tr>
 *     <tr><td>4</td><td> Client Hash</td><td>...</td></tr>
 *     <tr><td>5</td><td>Token</td><td>...</td></tr>
 *     <tr><td>6</td><td>Receipt Type</td><td>ATTEST or RECEIPT</td></tr>
 *     <tr><td>12</td><td>Creation Time</td><td>2020-06-22T14:40:08.819Z</td></tr>
 *     <tr><td>17</td><td>Risk Metric</td><td>5</td></tr>
 *     <tr><td>19</td><td>Not Before</td><td>2020-07-22T14:40:38.819Z</td></tr>
 *     <tr><td>21</td><td>Expiration Time</td><td> 2020-08-22T14:40:38.819Z</td></tr>
 * </table>
 *
 * <a
 * href="https://developer.apple.com/documentation/devicecheck/assessing_fraud_risk?language=objc">Assessing
 * Fraud Risk</a>
 */
public enum IOSReceiptAttribute {
  APP_ID(2) {
    @Override
    public Object getValue(byte[] bytes) {
      return toStringFunction.apply(bytes);
    }
  },
  ATTESTED_PUBLIC_KEY(3) {
    @Override
    public Object getValue(byte[] bytes) {
      return CryptoLoader.getCertificateFromPem(bytes);
    }
  },
  CLIENT_HASH(4),
  TOKEN(5) {
    @Override
    public Object getValue(byte[] bytes) {
      return toStringFunction.apply(bytes);
    }
  },
  RECEIPT_TYPE(6) {
    @Override
    public Object getValue(byte[] bytes) {
      return toIOSReceiptTypeFunction.apply(bytes);
    }
  },
  CREATION_TIME(12) {
    @Override
    public Object getValue(byte[] bytes) {
      return toInstantFunction.apply(bytes);
    }
  },
  RISK_METRIC(17) {
    @Override
    public Object getValue(byte[] bytes) {
      return toIntegerFunction.applyAsInt(bytes);
    }

    @Override
    public String getDeviceHealthKey() {
      return "riskMetric";
    }
  },
  NOT_BEFORE(19) {
    @Override
    public Object getValue(byte[] bytes) {
      return toInstantFunction.apply(bytes);
    }
  },
  EXPIRATION_TIME(21) {
    @Override
    public Object getValue(byte[] bytes) {
      return toInstantFunction.apply(bytes);
    }
  };

  private static final Logger LOG = Logger.getLogger(IOSReceiptAttribute.class);
  private final int tagNumber;

  IOSReceiptAttribute(int tagNumber) {
    this.tagNumber = tagNumber;
  }

  protected Object getValue(byte[] bytes) {
    return bytes;
  }

  public Object getConvertedValue(byte[] bytes) {
    if (bytes == null || bytes.length == 0) {
      UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s - The receipt attribute with index %d and key %s is missing",
          traceId, tagNumber, name());
      throw new GMServiceRuntimeException(UNREADABLE_RECEIPT, traceId);
    }
    return getValue(bytes);
  }

  public String getDeviceHealthKey() {
    return name().toLowerCase();
  }

  static Optional<IOSReceiptAttribute> defineByTagNumber(int tagNumber) {
    return Arrays.stream(values()).filter(t -> t.tagNumber == tagNumber).findAny();
  }

  private static Function<byte[], String> toStringFunction =
      bytes -> new String(bytes, StandardCharsets.UTF_8);

  private static ToIntFunction<byte[]> toIntegerFunction =
      bytes -> Integer.parseInt(toStringFunction.apply(bytes));

  private static Function<byte[], Instant> toInstantFunction =
      bytes -> Instant.parse(toStringFunction.apply(bytes));

  private static Function<byte[], IOSReceipt.IOSReceiptType> toIOSReceiptTypeFunction =
      bytes -> IOSReceipt.IOSReceiptType.valueOf(toStringFunction.apply(bytes));
}
