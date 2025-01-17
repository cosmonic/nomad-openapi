/*
 * Nomad
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.1.4
 * Contact: support@hashicorp.com
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client

import (
	"encoding/json"
)

// JobDeregisterResponse struct for JobDeregisterResponse
type JobDeregisterResponse struct {
	EvalCreateIndex *int32 `json:"EvalCreateIndex,omitempty"`
	EvalID *string `json:"EvalID,omitempty"`
	JobModifyIndex *int32 `json:"JobModifyIndex,omitempty"`
	KnownLeader *bool `json:"KnownLeader,omitempty"`
	LastContact *int64 `json:"LastContact,omitempty"`
	LastIndex *int32 `json:"LastIndex,omitempty"`
	RequestTime *int64 `json:"RequestTime,omitempty"`
}

// NewJobDeregisterResponse instantiates a new JobDeregisterResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewJobDeregisterResponse() *JobDeregisterResponse {
	this := JobDeregisterResponse{}
	return &this
}

// NewJobDeregisterResponseWithDefaults instantiates a new JobDeregisterResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewJobDeregisterResponseWithDefaults() *JobDeregisterResponse {
	this := JobDeregisterResponse{}
	return &this
}

// GetEvalCreateIndex returns the EvalCreateIndex field value if set, zero value otherwise.
func (o *JobDeregisterResponse) GetEvalCreateIndex() int32 {
	if o == nil || o.EvalCreateIndex == nil {
		var ret int32
		return ret
	}
	return *o.EvalCreateIndex
}

// GetEvalCreateIndexOk returns a tuple with the EvalCreateIndex field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *JobDeregisterResponse) GetEvalCreateIndexOk() (*int32, bool) {
	if o == nil || o.EvalCreateIndex == nil {
		return nil, false
	}
	return o.EvalCreateIndex, true
}

// HasEvalCreateIndex returns a boolean if a field has been set.
func (o *JobDeregisterResponse) HasEvalCreateIndex() bool {
	if o != nil && o.EvalCreateIndex != nil {
		return true
	}

	return false
}

// SetEvalCreateIndex gets a reference to the given int32 and assigns it to the EvalCreateIndex field.
func (o *JobDeregisterResponse) SetEvalCreateIndex(v int32) {
	o.EvalCreateIndex = &v
}

// GetEvalID returns the EvalID field value if set, zero value otherwise.
func (o *JobDeregisterResponse) GetEvalID() string {
	if o == nil || o.EvalID == nil {
		var ret string
		return ret
	}
	return *o.EvalID
}

// GetEvalIDOk returns a tuple with the EvalID field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *JobDeregisterResponse) GetEvalIDOk() (*string, bool) {
	if o == nil || o.EvalID == nil {
		return nil, false
	}
	return o.EvalID, true
}

// HasEvalID returns a boolean if a field has been set.
func (o *JobDeregisterResponse) HasEvalID() bool {
	if o != nil && o.EvalID != nil {
		return true
	}

	return false
}

// SetEvalID gets a reference to the given string and assigns it to the EvalID field.
func (o *JobDeregisterResponse) SetEvalID(v string) {
	o.EvalID = &v
}

// GetJobModifyIndex returns the JobModifyIndex field value if set, zero value otherwise.
func (o *JobDeregisterResponse) GetJobModifyIndex() int32 {
	if o == nil || o.JobModifyIndex == nil {
		var ret int32
		return ret
	}
	return *o.JobModifyIndex
}

// GetJobModifyIndexOk returns a tuple with the JobModifyIndex field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *JobDeregisterResponse) GetJobModifyIndexOk() (*int32, bool) {
	if o == nil || o.JobModifyIndex == nil {
		return nil, false
	}
	return o.JobModifyIndex, true
}

// HasJobModifyIndex returns a boolean if a field has been set.
func (o *JobDeregisterResponse) HasJobModifyIndex() bool {
	if o != nil && o.JobModifyIndex != nil {
		return true
	}

	return false
}

// SetJobModifyIndex gets a reference to the given int32 and assigns it to the JobModifyIndex field.
func (o *JobDeregisterResponse) SetJobModifyIndex(v int32) {
	o.JobModifyIndex = &v
}

// GetKnownLeader returns the KnownLeader field value if set, zero value otherwise.
func (o *JobDeregisterResponse) GetKnownLeader() bool {
	if o == nil || o.KnownLeader == nil {
		var ret bool
		return ret
	}
	return *o.KnownLeader
}

// GetKnownLeaderOk returns a tuple with the KnownLeader field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *JobDeregisterResponse) GetKnownLeaderOk() (*bool, bool) {
	if o == nil || o.KnownLeader == nil {
		return nil, false
	}
	return o.KnownLeader, true
}

// HasKnownLeader returns a boolean if a field has been set.
func (o *JobDeregisterResponse) HasKnownLeader() bool {
	if o != nil && o.KnownLeader != nil {
		return true
	}

	return false
}

// SetKnownLeader gets a reference to the given bool and assigns it to the KnownLeader field.
func (o *JobDeregisterResponse) SetKnownLeader(v bool) {
	o.KnownLeader = &v
}

// GetLastContact returns the LastContact field value if set, zero value otherwise.
func (o *JobDeregisterResponse) GetLastContact() int64 {
	if o == nil || o.LastContact == nil {
		var ret int64
		return ret
	}
	return *o.LastContact
}

// GetLastContactOk returns a tuple with the LastContact field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *JobDeregisterResponse) GetLastContactOk() (*int64, bool) {
	if o == nil || o.LastContact == nil {
		return nil, false
	}
	return o.LastContact, true
}

// HasLastContact returns a boolean if a field has been set.
func (o *JobDeregisterResponse) HasLastContact() bool {
	if o != nil && o.LastContact != nil {
		return true
	}

	return false
}

// SetLastContact gets a reference to the given int64 and assigns it to the LastContact field.
func (o *JobDeregisterResponse) SetLastContact(v int64) {
	o.LastContact = &v
}

// GetLastIndex returns the LastIndex field value if set, zero value otherwise.
func (o *JobDeregisterResponse) GetLastIndex() int32 {
	if o == nil || o.LastIndex == nil {
		var ret int32
		return ret
	}
	return *o.LastIndex
}

// GetLastIndexOk returns a tuple with the LastIndex field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *JobDeregisterResponse) GetLastIndexOk() (*int32, bool) {
	if o == nil || o.LastIndex == nil {
		return nil, false
	}
	return o.LastIndex, true
}

// HasLastIndex returns a boolean if a field has been set.
func (o *JobDeregisterResponse) HasLastIndex() bool {
	if o != nil && o.LastIndex != nil {
		return true
	}

	return false
}

// SetLastIndex gets a reference to the given int32 and assigns it to the LastIndex field.
func (o *JobDeregisterResponse) SetLastIndex(v int32) {
	o.LastIndex = &v
}

// GetRequestTime returns the RequestTime field value if set, zero value otherwise.
func (o *JobDeregisterResponse) GetRequestTime() int64 {
	if o == nil || o.RequestTime == nil {
		var ret int64
		return ret
	}
	return *o.RequestTime
}

// GetRequestTimeOk returns a tuple with the RequestTime field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *JobDeregisterResponse) GetRequestTimeOk() (*int64, bool) {
	if o == nil || o.RequestTime == nil {
		return nil, false
	}
	return o.RequestTime, true
}

// HasRequestTime returns a boolean if a field has been set.
func (o *JobDeregisterResponse) HasRequestTime() bool {
	if o != nil && o.RequestTime != nil {
		return true
	}

	return false
}

// SetRequestTime gets a reference to the given int64 and assigns it to the RequestTime field.
func (o *JobDeregisterResponse) SetRequestTime(v int64) {
	o.RequestTime = &v
}

func (o JobDeregisterResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.EvalCreateIndex != nil {
		toSerialize["EvalCreateIndex"] = o.EvalCreateIndex
	}
	if o.EvalID != nil {
		toSerialize["EvalID"] = o.EvalID
	}
	if o.JobModifyIndex != nil {
		toSerialize["JobModifyIndex"] = o.JobModifyIndex
	}
	if o.KnownLeader != nil {
		toSerialize["KnownLeader"] = o.KnownLeader
	}
	if o.LastContact != nil {
		toSerialize["LastContact"] = o.LastContact
	}
	if o.LastIndex != nil {
		toSerialize["LastIndex"] = o.LastIndex
	}
	if o.RequestTime != nil {
		toSerialize["RequestTime"] = o.RequestTime
	}
	return json.Marshal(toSerialize)
}

type NullableJobDeregisterResponse struct {
	value *JobDeregisterResponse
	isSet bool
}

func (v NullableJobDeregisterResponse) Get() *JobDeregisterResponse {
	return v.value
}

func (v *NullableJobDeregisterResponse) Set(val *JobDeregisterResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableJobDeregisterResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableJobDeregisterResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableJobDeregisterResponse(val *JobDeregisterResponse) *NullableJobDeregisterResponse {
	return &NullableJobDeregisterResponse{value: val, isSet: true}
}

func (v NullableJobDeregisterResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableJobDeregisterResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


