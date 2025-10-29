# security/vault/client.py
import hvac
import os
from typing import Dict, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class SecretMetadata:
    path: str
    ttl: int
    created_time: datetime
    expiry_time: datetime

class VaultClient:
    def __init__(self, vault_url: str, vault_token: str = None):
        self.client = hvac.Client(url=vault_url, token=vault_token)
        self._secret_cache = {}

    def get_database_credentials(self, role_name: str) -> Dict[str, str]:
        """Get dynamic database credentials"""
        try:
            response = self.client.secrets.database.generate_credentials(
                name=role_name,
                mount_point='database'
            )

            credentials = response['data']
            # Cache with TTL tracking
            ttl = response['lease_duration']
            self._secret_cache[f"db_{role_name}"] = SecretMetadata(
                path=f"database/creds/{role_name}",
                ttl=ttl,
                created_time=datetime.now(),
                expiry_time=datetime.now() + timedelta(seconds=ttl-300)  # 5min buffer
            )

            return {
                'username': credentials['username'],
                'password': credentials['password'],
                'ttl': ttl
            }
        except Exception as e:
            raise Exception(f"Failed to get database credentials: {e}")

    def get_cloud_credentials(self, cloud_provider: str, role: str) -> Dict[str, str]:
        """Get short-lived cloud provider credentials"""
        mount_point = f"{cloud_provider}-secrets"

        try:
            if cloud_provider == "aws":
                response = self.client.secrets.aws.generate_credentials(
                    name=role,
                    mount_point=mount_point
                )
                return {
                    'access_key': response['data']['access_key'],
                    'secret_key': response['data']['secret_key'],
                    'security_token': response['data']['security_token'],
                    'ttl': response['lease_duration']
                }
            elif cloud_provider == "azure":
                response = self.client.secrets.azure.generate_credentials(
                    name=role,
                    mount_point=mount_point
                )
                return response['data']
            elif cloud_provider == "gcp":
                response = self.client.secrets.gcp.generate_access_token(
                    name=role,
                    mount_point=mount_point
                )
                return response['data']
        except Exception as e:
            raise Exception(f"Failed to get {cloud_provider} credentials: {e}")

    def should_refresh_secret(self, cache_key: str) -> bool:
        """Check if a cached secret should be refreshed"""
        if cache_key not in self._secret_cache:
            return True

        metadata = self._secret_cache[cache_key]
        return datetime.now() >= metadata.expiry_time