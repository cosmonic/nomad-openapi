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

// FuzzySearchRequest struct for FuzzySearchRequest
type FuzzySearchRequest struct {
	AllowStale *bool              `json:"AllowStale,omitempty"`
	AuthToken  *string            `json:"XNomadToken,omitempty"`
	Context    *string            `json:"Context,omitempty"`
	Namespace  *string            `json:"Namespace,omitempty"`
	NextToken  *string            `json:"NextToken,omitempty"`
	Params     *map[string]string `json:"Params,omitempty"`
	PerPage    *int32             `json:"PerPage,omitempty"`
	Prefix     *string            `json:"Prefix,omitempty"`
	Region     *string            `json:"Region,omitempty"`
	Text       *string            `json:"Text,omitempty"`
	WaitIndex  *int32             `json:"Index,omitempty"`
	WaitTime   *int64             `json:"Wait,omitempty"`
}

// NewFuzzySearchRequest instantiates a new FuzzySearchRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFuzzySearchRequest() *FuzzySearchRequest {
	this := FuzzySearchRequest{}
	return &this
}

// NewFuzzySearchRequestWithDefaults instantiates a new FuzzySearchRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFuzzySearchRequestWithDefaults() *FuzzySearchRequest {
	this := FuzzySearchRequest{}
	return &this
}

// GetAllowStale returns the AllowStale field value if set, zero value otherwise.
func (o *FuzzySearchRequest) GetAllowStale() bool {
	if o == nil || o.AllowStale == nil {
		var ret bool
		return ret
	}
	return *o.AllowStale
}

// GetAllowStaleOk returns a tuple with the AllowStale field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FuzzySearchRequest) GetAllowStaleOk() (*bool, bool) {
	if o == nil || o.AllowStale == nil {
		return nil, false
	}
	return o.AllowStale, true
}

// HasAllowStale returns a boolean if a field has been set.
func (o *FuzzySearchRequest) HasAllowStale() bool {
	if o != nil && o.AllowStale != nil {
		return true
	}

	return false
}

// SetAllowStale gets a reference to the given bool and assigns it to the AllowStale field.
func (o *FuzzySearchRequest) SetAllowStale(v bool) {
	o.AllowStale = &v
}

// GetAuthToken returns the AuthToken field value if set, zero value otherwise.
func (o *FuzzySearchRequest) GetAuthToken() string {
	if o == nil || o.AuthToken == nil {
		var ret string
		return ret
	}
	return *o.AuthToken
}

// GetAuthTokenOk returns a tuple with the AuthToken field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FuzzySearchRequest) GetAuthTokenOk() (*string, bool) {
	if o == nil || o.AuthToken == nil {
		return nil, false
	}
	return o.AuthToken, true
}

// HasAuthToken returns a boolean if a field has been set.
func (o *FuzzySearchRequest) HasAuthToken() bool {
	if o != nil && o.AuthToken != nil {
		return true
	}

	return false
}

// SetAuthToken gets a reference to the given string and assigns it to the AuthToken field.
func (o *FuzzySearchRequest) SetAuthToken(v string) {
	o.AuthToken = &v
}

// GetContext returns the Context field value if set, zero value otherwise.
func (o *FuzzySearchRequest) GetContext() string {
	if o == nil || o.Context == nil {
		var ret string
		return ret
	}
	return *o.Context
}

// GetContextOk returns a tuple with the Context field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FuzzySearchRequest) GetContextOk() (*string, bool) {
	if o == nil || o.Context == nil {
		return nil, false
	}
	return o.Context, true
}

// HasContext returns a boolean if a field has been set.
func (o *FuzzySearchRequest) HasContext() bool {
	if o != nil && o.Context != nil {
		return true
	}

	return false
}

// SetContext gets a reference to the given string and assigns it to the Context field.
func (o *FuzzySearchRequest) SetContext(v string) {
	o.Context = &v
}

// GetNamespace returns the Namespace field value if set, zero value otherwise.
func (o *FuzzySearchRequest) GetNamespace() string {
	if o == nil || o.Namespace == nil {
		var ret string
		return ret
	}
	return *o.Namespace
}

// GetNamespaceOk returns a tuple with the Namespace field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FuzzySearchRequest) GetNamespaceOk() (*string, bool) {
	if o == nil || o.Namespace == nil {
		return nil, false
	}
	return o.Namespace, true
}

// HasNamespace returns a boolean if a field has been set.
func (o *FuzzySearchRequest) HasNamespace() bool {
	if o != nil && o.Namespace != nil {
		return true
	}

	return false
}

// SetNamespace gets a reference to the given string and assigns it to the Namespace field.
func (o *FuzzySearchRequest) SetNamespace(v string) {
	o.Namespace = &v
}

// GetNextToken returns the NextToken field value if set, zero value otherwise.
func (o *FuzzySearchRequest) GetNextToken() string {
	if o == nil || o.NextToken == nil {
		var ret string
		return ret
	}
	return *o.NextToken
}

// GetNextTokenOk returns a tuple with the NextToken field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FuzzySearchRequest) GetNextTokenOk() (*string, bool) {
	if o == nil || o.NextToken == nil {
		return nil, false
	}
	return o.NextToken, true
}

// HasNextToken returns a boolean if a field has been set.
func (o *FuzzySearchRequest) HasNextToken() bool {
	if o != nil && o.NextToken != nil {
		return true
	}

	return false
}

// SetNextToken gets a reference to the given string and assigns it to the NextToken field.
func (o *FuzzySearchRequest) SetNextToken(v string) {
	o.NextToken = &v
}

// GetParams returns the Params field value if set, zero value otherwise.
func (o *FuzzySearchRequest) GetParams() map[string]string {
	if o == nil || o.Params == nil {
		var ret map[string]string
		return ret
	}
	return *o.Params
}

// GetParamsOk returns a tuple with the Params field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FuzzySearchRequest) GetParamsOk() (*map[string]string, bool) {
	if o == nil || o.Params == nil {
		return nil, false
	}
	return o.Params, true
}

// HasParams returns a boolean if a field has been set.
func (o *FuzzySearchRequest) HasParams() bool {
	if o != nil && o.Params != nil {
		return true
	}

	return false
}

// SetParams gets a reference to the given map[string]string and assigns it to the Params field.
func (o *FuzzySearchRequest) SetParams(v map[string]string) {
	o.Params = &v
}

// GetPerPage returns the PerPage field value if set, zero value otherwise.
func (o *FuzzySearchRequest) GetPerPage() int32 {
	if o == nil || o.PerPage == nil {
		var ret int32
		return ret
	}
	return *o.PerPage
}

// GetPerPageOk returns a tuple with the PerPage field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FuzzySearchRequest) GetPerPageOk() (*int32, bool) {
	if o == nil || o.PerPage == nil {
		return nil, false
	}
	return o.PerPage, true
}

// HasPerPage returns a boolean if a field has been set.
func (o *FuzzySearchRequest) HasPerPage() bool {
	if o != nil && o.PerPage != nil {
		return true
	}

	return false
}

// SetPerPage gets a reference to the given int32 and assigns it to the PerPage field.
func (o *FuzzySearchRequest) SetPerPage(v int32) {
	o.PerPage = &v
}

// GetPrefix returns the Prefix field value if set, zero value otherwise.
func (o *FuzzySearchRequest) GetPrefix() string {
	if o == nil || o.Prefix == nil {
		var ret string
		return ret
	}
	return *o.Prefix
}

// GetPrefixOk returns a tuple with the Prefix field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FuzzySearchRequest) GetPrefixOk() (*string, bool) {
	if o == nil || o.Prefix == nil {
		return nil, false
	}
	return o.Prefix, true
}

// HasPrefix returns a boolean if a field has been set.
func (o *FuzzySearchRequest) HasPrefix() bool {
	if o != nil && o.Prefix != nil {
		return true
	}

	return false
}

// SetPrefix gets a reference to the given string and assigns it to the Prefix field.
func (o *FuzzySearchRequest) SetPrefix(v string) {
	o.Prefix = &v
}

// GetRegion returns the Region field value if set, zero value otherwise.
func (o *FuzzySearchRequest) GetRegion() string {
	if o == nil || o.Region == nil {
		var ret string
		return ret
	}
	return *o.Region
}

// GetRegionOk returns a tuple with the Region field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FuzzySearchRequest) GetRegionOk() (*string, bool) {
	if o == nil || o.Region == nil {
		return nil, false
	}
	return o.Region, true
}

// HasRegion returns a boolean if a field has been set.
func (o *FuzzySearchRequest) HasRegion() bool {
	if o != nil && o.Region != nil {
		return true
	}

	return false
}

// SetRegion gets a reference to the given string and assigns it to the Region field.
func (o *FuzzySearchRequest) SetRegion(v string) {
	o.Region = &v
}

// GetText returns the Text field value if set, zero value otherwise.
func (o *FuzzySearchRequest) GetText() string {
	if o == nil || o.Text == nil {
		var ret string
		return ret
	}
	return *o.Text
}

// GetTextOk returns a tuple with the Text field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FuzzySearchRequest) GetTextOk() (*string, bool) {
	if o == nil || o.Text == nil {
		return nil, false
	}
	return o.Text, true
}

// HasText returns a boolean if a field has been set.
func (o *FuzzySearchRequest) HasText() bool {
	if o != nil && o.Text != nil {
		return true
	}

	return false
}

// SetText gets a reference to the given string and assigns it to the Text field.
func (o *FuzzySearchRequest) SetText(v string) {
	o.Text = &v
}

// GetWaitIndex returns the WaitIndex field value if set, zero value otherwise.
func (o *FuzzySearchRequest) GetWaitIndex() int32 {
	if o == nil || o.WaitIndex == nil {
		var ret int32
		return ret
	}
	return *o.WaitIndex
}

// GetWaitIndexOk returns a tuple with the WaitIndex field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FuzzySearchRequest) GetWaitIndexOk() (*int32, bool) {
	if o == nil || o.WaitIndex == nil {
		return nil, false
	}
	return o.WaitIndex, true
}

// HasWaitIndex returns a boolean if a field has been set.
func (o *FuzzySearchRequest) HasWaitIndex() bool {
	if o != nil && o.WaitIndex != nil {
		return true
	}

	return false
}

// SetWaitIndex gets a reference to the given int32 and assigns it to the WaitIndex field.
func (o *FuzzySearchRequest) SetWaitIndex(v int32) {
	o.WaitIndex = &v
}

// GetWaitTime returns the WaitTime field value if set, zero value otherwise.
func (o *FuzzySearchRequest) GetWaitTime() int64 {
	if o == nil || o.WaitTime == nil {
		var ret int64
		return ret
	}
	return *o.WaitTime
}

// GetWaitTimeOk returns a tuple with the WaitTime field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FuzzySearchRequest) GetWaitTimeOk() (*int64, bool) {
	if o == nil || o.WaitTime == nil {
		return nil, false
	}
	return o.WaitTime, true
}

// HasWaitTime returns a boolean if a field has been set.
func (o *FuzzySearchRequest) HasWaitTime() bool {
	if o != nil && o.WaitTime != nil {
		return true
	}

	return false
}

// SetWaitTime gets a reference to the given int64 and assigns it to the WaitTime field.
func (o *FuzzySearchRequest) SetWaitTime(v int64) {
	o.WaitTime = &v
}

func (o FuzzySearchRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.AllowStale != nil {
		toSerialize["AllowStale"] = o.AllowStale
	}
	if o.AuthToken != nil {
		toSerialize["XNomadToken"] = o.AuthToken
	}
	if o.Context != nil {
		toSerialize["Context"] = o.Context
	}
	if o.Namespace != nil {
		toSerialize["Namespace"] = o.Namespace
	}
	if o.NextToken != nil {
		toSerialize["NextToken"] = o.NextToken
	}
	if o.Params != nil {
		toSerialize["Params"] = o.Params
	}
	if o.PerPage != nil {
		toSerialize["PerPage"] = o.PerPage
	}
	if o.Prefix != nil {
		toSerialize["Prefix"] = o.Prefix
	}
	if o.Region != nil {
		toSerialize["Region"] = o.Region
	}
	if o.Text != nil {
		toSerialize["Text"] = o.Text
	}
	if o.WaitIndex != nil {
		toSerialize["Index"] = o.WaitIndex
	}
	if o.WaitTime != nil {
		toSerialize["Wait"] = o.WaitTime
	}
	return json.Marshal(toSerialize)
}

type NullableFuzzySearchRequest struct {
	value *FuzzySearchRequest
	isSet bool
}

func (v NullableFuzzySearchRequest) Get() *FuzzySearchRequest {
	return v.value
}

func (v *NullableFuzzySearchRequest) Set(val *FuzzySearchRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableFuzzySearchRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableFuzzySearchRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFuzzySearchRequest(val *FuzzySearchRequest) *NullableFuzzySearchRequest {
	return &NullableFuzzySearchRequest{value: val, isSet: true}
}

func (v NullableFuzzySearchRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFuzzySearchRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
