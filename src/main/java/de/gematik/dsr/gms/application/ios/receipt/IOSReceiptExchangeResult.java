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

import de.gematik.dsr.gms.domain.DeviceReceiptEntityIOS;

/**
 * Result of the receipt exchange validation. Contains changed entity with the new receipt, if the
 * exchange was successful or the same, if no communication occurs with apple server.
 *
 * @param changedEntity the changed entity with new receipt or the old one, if no exchange happened.
 * @param receipt validated IOSReceipt based on the new received receipt bytes or old one, if no
 *     exchange happened.
 */
public record IOSReceiptExchangeResult(DeviceReceiptEntityIOS changedEntity, IOSReceipt receipt) {}
