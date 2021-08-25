/*
 * Nomad
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.1.3
 * Contact: support@hashicorp.com
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client

import (
	"encoding/json"
)

// JobValidateRequest struct for JobValidateRequest
type JobValidateRequest struct {
	Job *Job `json:"Job,omitempty"`
	Namespace *string `json:"Namespace,omitempty"`
	Region *string `json:"Region,omitempty"`
	SecretID *string `json:"SecretID,omitempty"`
}

// NewJobValidateRequest instantiates a new JobValidateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewJobValidateRequest() *JobValidateRequest {
	this := JobValidateRequest{}
	return &this
}

// NewJobValidateRequestWithDefaults instantiates a new JobValidateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewJobValidateRequestWithDefaults() *JobValidateRequest {
	this := JobValidateRequest{}
	return &this
}

// GetJob returns the Job field value if set, zero value otherwise.
func (o *JobValidateRequest) GetJob() Job {
	if o == nil || o.Job == nil {
		var ret Job
		return ret
	}
	return *o.Job
}

// GetJobOk returns a tuple with the Job field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *JobValidateRequest) GetJobOk() (*Job, bool) {
	if o == nil || o.Job == nil {
		return nil, false
	}
	return o.Job, true
}

// HasJob returns a boolean if a field has been set.
func (o *JobValidateRequest) HasJob() bool {
	if o != nil && o.Job != nil {
		return true
	}

	return false
}

// SetJob gets a reference to the given Job and assigns it to the Job field.
func (o *JobValidateRequest) SetJob(v Job) {
	o.Job = &v
}

// GetNamespace returns the Namespace field value if set, zero value otherwise.
func (o *JobValidateRequest) GetNamespace() string {
	if o == nil || o.Namespace == nil {
		var ret string
		return ret
	}
	return *o.Namespace
}

// GetNamespaceOk returns a tuple with the Namespace field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *JobValidateRequest) GetNamespaceOk() (*string, bool) {
	if o == nil || o.Namespace == nil {
		return nil, false
	}
	return o.Namespace, true
}

// HasNamespace returns a boolean if a field has been set.
func (o *JobValidateRequest) HasNamespace() bool {
	if o != nil && o.Namespace != nil {
		return true
	}

	return false
}

// SetNamespace gets a reference to the given string and assigns it to the Namespace field.
func (o *JobValidateRequest) SetNamespace(v string) {
	o.Namespace = &v
}

// GetRegion returns the Region field value if set, zero value otherwise.
func (o *JobValidateRequest) GetRegion() string {
	if o == nil || o.Region == nil {
		var ret string
		return ret
	}
	return *o.Region
}

// GetRegionOk returns a tuple with the Region field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *JobValidateRequest) GetRegionOk() (*string, bool) {
	if o == nil || o.Region == nil {
		return nil, false
	}
	return o.Region, true
}

// HasRegion returns a boolean if a field has been set.
func (o *JobValidateRequest) HasRegion() bool {
	if o != nil && o.Region != nil {
		return true
	}

	return false
}

// SetRegion gets a reference to the given string and assigns it to the Region field.
func (o *JobValidateRequest) SetRegion(v string) {
	o.Region = &v
}

// GetSecretID returns the SecretID field value if set, zero value otherwise.
func (o *JobValidateRequest) GetSecretID() string {
	if o == nil || o.SecretID == nil {
		var ret string
		return ret
	}
	return *o.SecretID
}

// GetSecretIDOk returns a tuple with the SecretID field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *JobValidateRequest) GetSecretIDOk() (*string, bool) {
	if o == nil || o.SecretID == nil {
		return nil, false
	}
	return o.SecretID, true
}

// HasSecretID returns a boolean if a field has been set.
func (o *JobValidateRequest) HasSecretID() bool {
	if o != nil && o.SecretID != nil {
		return true
	}

	return false
}

// SetSecretID gets a reference to the given string and assigns it to the SecretID field.
func (o *JobValidateRequest) SetSecretID(v string) {
	o.SecretID = &v
}

func (o JobValidateRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Job != nil {
		toSerialize["Job"] = o.Job
	}
	if o.Namespace != nil {
		toSerialize["Namespace"] = o.Namespace
	}
	if o.Region != nil {
		toSerialize["Region"] = o.Region
	}
	if o.SecretID != nil {
		toSerialize["SecretID"] = o.SecretID
	}
	return json.Marshal(toSerialize)
}

type NullableJobValidateRequest struct {
	value *JobValidateRequest
	isSet bool
}

func (v NullableJobValidateRequest) Get() *JobValidateRequest {
	return v.value
}

func (v *NullableJobValidateRequest) Set(val *JobValidateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableJobValidateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableJobValidateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableJobValidateRequest(val *JobValidateRequest) *NullableJobValidateRequest {
	return &NullableJobValidateRequest{value: val, isSet: true}
}

func (v NullableJobValidateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableJobValidateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


