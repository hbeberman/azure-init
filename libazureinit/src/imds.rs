// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use reqwest;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;
use reqwest::Client;

use serde::Deserialize;
use serde_json;
use serde_json::Value;

use crate::error::Error;

#[derive(Debug, Deserialize, PartialEq, Clone)]
pub struct PublicKeys {
    #[serde(rename = "keyData")]
    pub key_data: String,
    #[serde(rename = "path")]
    pub path: String,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
pub struct NetInterface {
    #[serde(rename = "ipv4")]
    pub ipv4: IPInfo,
    #[serde(rename = "ipv6")]
    pub ipv6: IPInfo,
    #[serde(rename = "macAddress")]
    pub mac_address: String,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
pub struct IPInfo {
    #[serde(rename = "ipAddress")]
    pub ip_address: Vec<IpAddress>,
    #[serde(rename = "subnet", default)]
    pub subnet: Vec<Subnet>,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
pub struct IpAddress {
    #[serde(rename = "privateIpAddress")]
    pub private_ip_address: String,
    #[serde(rename = "publicIpAddress")]
    pub public_ip_address: String,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
pub struct Subnet {
    #[serde(rename = "address")]
    pub address: String,
    #[serde(rename = "prefix")]
    pub prefix: String,
}

pub async fn query_imds(client: &Client) -> Result<String, Error> {
    let url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";
    let mut headers = HeaderMap::new();

    headers.insert("Metadata", HeaderValue::from_static("true"));

    let request = client.get(url).headers(headers);
    let response = request.send().await?;

    if response.status().is_success() {
        let imds_body = response.text().await?;

        Ok(imds_body)
    } else {
        Err(Error::HttpStatus {
            endpoint: url.to_owned(),
            status: response.status(),
        })
    }
}

pub fn get_ssh_keys(imds_body: String) -> Result<Vec<PublicKeys>, Error> {
    let data: Value = serde_json::from_str(&imds_body)?;
    let public_keys =
        Vec::<PublicKeys>::deserialize(&data["compute"]["publicKeys"])?;

    Ok(public_keys)
}

pub fn get_username(imds_body: String) -> Result<String, Error> {
    let data: Value = serde_json::from_str(&imds_body)?;
    let username =
        String::deserialize(&data["compute"]["osProfile"]["adminUsername"])?;

    Ok(username)
}

pub fn get_hostname(imds_body: String) -> Result<String, Error> {
    let data: Value = serde_json::from_str(&imds_body)?;
    let hostname =
        String::deserialize(&data["compute"]["osProfile"]["computerName"])?;

    Ok(hostname)
}

pub fn is_password_authentication_disabled(
    imds_body: &str,
) -> Result<bool, Error> {
    let data: Value = serde_json::from_str(imds_body)?;

    let provision_with_password = String::deserialize(
        &data["compute"]["osProfile"]["disablePasswordAuthentication"],
    )?;

    if provision_with_password == "true" {
        return Ok(true);
    }

    Ok(false)
}

pub fn get_networking(imds_body: String) -> Result<Vec<NetInterface>, Error> {
    let data: Value = serde_json::from_str(&imds_body)?;
    let net_interfaces =
        Vec::<NetInterface>::deserialize(&data["network"]["interface"])?;

    Ok(net_interfaces)
}

#[cfg(test)]
mod tests {
    use super::{
        get_hostname, get_ssh_keys, get_username,
        is_password_authentication_disabled, get_networking,
    };

    #[test]
    fn test_get_ssh_keys() {
        let file_body = r#"
        {
            "compute": {
              "azEnvironment": "AzurePublicCloud",
              "customData": "",
              "publicKeys": [
                {
                  "keyData": "ssh-rsa test_key1",
                  "path": "/path/to/.ssh/authorized_keys"
                },
                {
                    "keyData": "ssh-rsa test_key2",
                    "path": "/path/to/.ssh/authorized_keys"
                }
              ]
            }
        }"#
        .to_string();

        let public_keys = get_ssh_keys(file_body)
            .expect("Failed to obtain ssh keys from the JSON file.");

        assert_eq!(public_keys[0].key_data, "ssh-rsa test_key1".to_string());
        assert_eq!(public_keys[1].key_data, "ssh-rsa test_key2".to_string());
    }

    #[test]
    fn test_get_username() {
        let file_body = r#"
        {
            "compute": {
              "azEnvironment": "cloud_env",
              "customData": "",
              "evictionPolicy": "",
              "isHostCompatibilityLayerVm": "false",
              "licenseType": "",
              "location": "eastus",
              "name": "AzTux-MinProvAgent-Test-0001",
              "offer": "0001-com-ubuntu-server-focal",
              "osProfile": {
                "adminUsername": "MinProvAgentUser",
                "computerName": "AzTux-MinProvAgent-Test-0001",
                "disablePasswordAuthentication": "true"
              }
            }
        }"#
        .to_string();

        let username =
            get_username(file_body).expect("Failed to get username.");

        assert_eq!(username, "MinProvAgentUser".to_string());
    }

    #[test]
    fn test_get_hostname() {
        let file_body = r#"
        {
            "compute": {
              "azEnvironment": "cloud_env",
              "customData": "",
              "evictionPolicy": "",
              "isHostCompatibilityLayerVm": "false",
              "licenseType": "",
              "location": "eastus",
              "name": "AzTux-MinProvAgent-Test-0001",
              "offer": "0001-com-ubuntu-server-focal",
              "osProfile": {
                "adminUsername": "MinProvAgentUser",
                "computerName": "AzTux-MinProvAgent-Test-0001",
                "disablePasswordAuthentication": "true"
              }
            }
        }"#
        .to_string();

        let hostname =
            get_hostname(file_body).expect("Failed to get hostname.");

        assert_eq!(hostname, "AzTux-MinProvAgent-Test-0001".to_string());
    }

    #[test]
    fn test_provision_with_password_true() {
        let file_body = r#"
        {
            "compute": {
              "azEnvironment": "cloud_env",
              "customData": "",
              "evictionPolicy": "",
              "isHostCompatibilityLayerVm": "false",
              "licenseType": "",
              "location": "eastus",
              "name": "AzTux-MinProvAgent-Test-0001",
              "offer": "0001-com-ubuntu-server-focal",
              "osProfile": {
                "adminUsername": "MinProvAgentUser",
                "computerName": "AzTux-MinProvAgent-Test-0001",
                "disablePasswordAuthentication": "true"
              }
            }
        }"#
        .to_string();

        let provision_with_password =
            is_password_authentication_disabled(&file_body)
                .expect("Failed to interpret disablePasswordAuthentication.");

        assert_eq!(provision_with_password, true);
    }

    #[test]
    fn test_get_networking() {
        let file_body = r#"
        {
            "network": {
                "interface": [
                  {
                    "ipv4": {
                      "ipAddress": [
                        {
                          "privateIpAddress": "10.0.0.4",
                          "publicIpAddress": ""
                        }
                      ],
                      "subnet": [
                        {
                          "address": "10.0.0.0",
                          "prefix": "24"
                        }
                      ]
                    },
                    "ipv6": {
                      "ipAddress": []
                    },
                    "macAddress": "1234567890AB"
                  }
                ]
              }
        }"#
        .to_string();

        let networking =
            get_networking(file_body).expect("Failed to get networking.");

        assert_eq!(networking[0].mac_address, "1234567890AB".to_string());
        assert_eq!(networking[0].ipv4.ip_address[0].private_ip_address, "10.0.0.4".to_string());
    }
}
