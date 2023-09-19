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

package de.gematik.dsr.gms.infrastructure;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import de.gematik.dsr.gms.application.MasterDataRepository;
import io.smallrye.jwt.util.ResourceUtils;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class InMemoryMasterDataRepository implements MasterDataRepository {

  private final ObjectMapper objectMapper;
  private final MasterData masterData;

  @Inject
  public InMemoryMasterDataRepository(
      final ObjectMapper objectMapper,
      @ConfigProperty(name = "master.data.template-path") String masterDataTemplatePath) {
    this.objectMapper = objectMapper;
    this.masterData = convert(masterDataTemplatePath);
  }

  private MasterData convert(final String masterDataTemplatePath) {
    try {
      InputStream inputStream = ResourceUtils.getResourceStream(masterDataTemplatePath);
      return objectMapper.readValue(inputStream, InMemoryMasterDataRepository.MasterData.class);
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "Failed to convert masterDataTemplatePath into MasterData", e);
    }
  }

  @Override
  public List<AvailablePackage> getAvailablePackages() {
    return Optional.ofNullable(masterData)
        .map(MasterData::availablePackages)
        .orElse(Collections.emptyList());
  }

  @Override
  public List<AppId> getAvailableAppIds() {
    return Optional.ofNullable(masterData)
        .map(MasterData::availableAppIds)
        .orElse(Collections.emptyList());
  }

  @Override
  public List<String> getAvailableTrustedSDKVersions() {
    return Optional.ofNullable(masterData)
        .map(MasterData::trustedSDKVersions)
        .orElse(Collections.emptyList());
  }

  public record MasterData(
      @JsonDeserialize(contentAs = AvailablePackageImpl.class)
          List<AvailablePackage> availablePackages,
      @JsonDeserialize(contentAs = AppIdImpl.class) List<AppId> availableAppIds,
      List<String> trustedSDKVersions) {}

  record AvailablePackageImpl(String packageName, long version, String certificateSha256Digest)
      implements MasterDataRepository.AvailablePackage {

    @Override
    public String getPackageName() {
      return packageName();
    }

    @Override
    public long getVersion() {
      return version();
    }

    @Override
    public String getCertificateSha256Digest() {
      return certificateSha256Digest();
    }
  }

  record AppIdImpl(String teamId, String bundledIdentifier) implements MasterDataRepository.AppId {
    @Override
    public String getTeamId() {
      return teamId();
    }

    @Override
    public String getBundledIdentifier() {
      return bundledIdentifier();
    }
  }
}
