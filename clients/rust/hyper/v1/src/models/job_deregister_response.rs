/*
 * Nomad
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 1.1.4
 * Contact: support@hashicorp.com
 * Generated by: https://openapi-generator.tech
 */




#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JobDeregisterResponse {
    #[serde(rename = "EvalCreateIndex", skip_serializing_if = "Option::is_none")]
    pub eval_create_index: Option<i32>,
    #[serde(rename = "EvalID", skip_serializing_if = "Option::is_none")]
    pub eval_id: Option<String>,
    #[serde(rename = "JobModifyIndex", skip_serializing_if = "Option::is_none")]
    pub job_modify_index: Option<i32>,
    #[serde(rename = "KnownLeader", skip_serializing_if = "Option::is_none")]
    pub known_leader: Option<bool>,
    #[serde(rename = "LastContact", skip_serializing_if = "Option::is_none")]
    pub last_contact: Option<i64>,
    #[serde(rename = "LastIndex", skip_serializing_if = "Option::is_none")]
    pub last_index: Option<i32>,
    #[serde(rename = "RequestTime", skip_serializing_if = "Option::is_none")]
    pub request_time: Option<i64>,
}

impl JobDeregisterResponse {
    pub fn new() -> JobDeregisterResponse {
        JobDeregisterResponse {
            eval_create_index: None,
            eval_id: None,
            job_modify_index: None,
            known_leader: None,
            last_contact: None,
            last_index: None,
            request_time: None,
        }
    }
}

