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

// OneTimeTokenExchangeRequest struct for OneTimeTokenExchangeRequest
type OneTimeTokenExchangeRequest struct {
	OneTimeSecretID *string `json:"OneTimeSecretID,omitempty"`
}

// NewOneTimeTokenExchangeRequest instantiates a new OneTimeTokenExchangeRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewOneTimeTokenExchangeRequest() *OneTimeTokenExchangeRequest {
	this := OneTimeTokenExchangeRequest{}
	return &this
}

// NewOneTimeTokenExchangeRequestWithDefaults instantiates a new OneTimeTokenExchangeRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewOneTimeTokenExchangeRequestWithDefaults() *OneTimeTokenExchangeRequest {
	this := OneTimeTokenExchangeRequest{}
	return &this
}

// GetOneTimeSecretID returns the OneTimeSecretID field value if set, zero value otherwise.
func (o *OneTimeTokenExchangeRequest) GetOneTimeSecretID() string {
	if o == nil || o.OneTimeSecretID == nil {
		var ret string
		return ret
	}
	return *o.OneTimeSecretID
}

// GetOneTimeSecretIDOk returns a tuple with the OneTimeSecretID field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *OneTimeTokenExchangeRequest) GetOneTimeSecretIDOk() (*string, bool) {
	if o == nil || o.OneTimeSecretID == nil {
		return nil, false
	}
	return o.OneTimeSecretID, true
}

// HasOneTimeSecretID returns a boolean if a field has been set.
func (o *OneTimeTokenExchangeRequest) HasOneTimeSecretID() bool {
	if o != nil && o.OneTimeSecretID != nil {
		return true
	}

	return false
}

// SetOneTimeSecretID gets a reference to the given string and assigns it to the OneTimeSecretID field.
func (o *OneTimeTokenExchangeRequest) SetOneTimeSecretID(v string) {
	o.OneTimeSecretID = &v
}

func (o OneTimeTokenExchangeRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.OneTimeSecretID != nil {
		toSerialize["OneTimeSecretID"] = o.OneTimeSecretID
	}
	return json.Marshal(toSerialize)
}

type NullableOneTimeTokenExchangeRequest struct {
	value *OneTimeTokenExchangeRequest
	isSet bool
}

func (v NullableOneTimeTokenExchangeRequest) Get() *OneTimeTokenExchangeRequest {
	return v.value
}

func (v *NullableOneTimeTokenExchangeRequest) Set(val *OneTimeTokenExchangeRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableOneTimeTokenExchangeRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableOneTimeTokenExchangeRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableOneTimeTokenExchangeRequest(val *OneTimeTokenExchangeRequest) *NullableOneTimeTokenExchangeRequest {
	return &NullableOneTimeTokenExchangeRequest{value: val, isSet: true}
}

func (v NullableOneTimeTokenExchangeRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableOneTimeTokenExchangeRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


