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
pub struct EvalOptions {
    #[serde(rename = "ForceReschedule", skip_serializing_if = "Option::is_none")]
    pub force_reschedule: Option<bool>,
}

impl EvalOptions {
    pub fn new() -> EvalOptions {
        EvalOptions {
            force_reschedule: None,
        }
    }
}

