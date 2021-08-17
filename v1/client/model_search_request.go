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

// SearchRequest struct for SearchRequest
type SearchRequest struct {
	AllowStale *bool              `json:"AllowStale,omitempty"`
	AuthToken  *string            `json:"XNomadToken,omitempty"`
	Context    *string            `json:"Context,omitempty"`
	Namespace  *string            `json:"Namespace,omitempty"`
	NextToken  *string            `json:"NextToken,omitempty"`
	Params     *map[string]string `json:"Params,omitempty"`
	PerPage    *int32             `json:"PerPage,omitempty"`
	Prefix     *string            `json:"Prefix,omitempty"`
	Region     *string            `json:"Region,omitempty"`
	WaitIndex  *int32             `json:"Index,omitempty"`
	WaitTime   *int64             `json:"Wait,omitempty"`
}

// NewSearchRequest instantiates a new SearchRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSearchRequest() *SearchRequest {
	this := SearchRequest{}
	return &this
}

// NewSearchRequestWithDefaults instantiates a new SearchRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSearchRequestWithDefaults() *SearchRequest {
	this := SearchRequest{}
	return &this
}

// GetAllowStale returns the AllowStale field value if set, zero value otherwise.
func (o *SearchRequest) GetAllowStale() bool {
	if o == nil || o.AllowStale == nil {
		var ret bool
		return ret
	}
	return *o.AllowStale
}

// GetAllowStaleOk returns a tuple with the AllowStale field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SearchRequest) GetAllowStaleOk() (*bool, bool) {
	if o == nil || o.AllowStale == nil {
		return nil, false
	}
	return o.AllowStale, true
}

// HasAllowStale returns a boolean if a field has been set.
func (o *SearchRequest) HasAllowStale() bool {
	if o != nil && o.AllowStale != nil {
		return true
	}

	return false
}

// SetAllowStale gets a reference to the given bool and assigns it to the AllowStale field.
func (o *SearchRequest) SetAllowStale(v bool) {
	o.AllowStale = &v
}

// GetAuthToken returns the AuthToken field value if set, zero value otherwise.
func (o *SearchRequest) GetAuthToken() string {
	if o == nil || o.AuthToken == nil {
		var ret string
		return ret
	}
	return *o.AuthToken
}

// GetAuthTokenOk returns a tuple with the AuthToken field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SearchRequest) GetAuthTokenOk() (*string, bool) {
	if o == nil || o.AuthToken == nil {
		return nil, false
	}
	return o.AuthToken, true
}

// HasAuthToken returns a boolean if a field has been set.
func (o *SearchRequest) HasAuthToken() bool {
	if o != nil && o.AuthToken != nil {
		return true
	}

	return false
}

// SetAuthToken gets a reference to the given string and assigns it to the AuthToken field.
func (o *SearchRequest) SetAuthToken(v string) {
	o.AuthToken = &v
}

// GetContext returns the Context field value if set, zero value otherwise.
func (o *SearchRequest) GetContext() string {
	if o == nil || o.Context == nil {
		var ret string
		return ret
	}
	return *o.Context
}

// GetContextOk returns a tuple with the Context field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SearchRequest) GetContextOk() (*string, bool) {
	if o == nil || o.Context == nil {
		return nil, false
	}
	return o.Context, true
}

// HasContext returns a boolean if a field has been set.
func (o *SearchRequest) HasContext() bool {
	if o != nil && o.Context != nil {
		return true
	}

	return false
}

// SetContext gets a reference to the given string and assigns it to the Context field.
func (o *SearchRequest) SetContext(v string) {
	o.Context = &v
}

// GetNamespace returns the Namespace field value if set, zero value otherwise.
func (o *SearchRequest) GetNamespace() string {
	if o == nil || o.Namespace == nil {
		var ret string
		return ret
	}
	return *o.Namespace
}

// GetNamespaceOk returns a tuple with the Namespace field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SearchRequest) GetNamespaceOk() (*string, bool) {
	if o == nil || o.Namespace == nil {
		return nil, false
	}
	return o.Namespace, true
}

// HasNamespace returns a boolean if a field has been set.
func (o *SearchRequest) HasNamespace() bool {
	if o != nil && o.Namespace != nil {
		return true
	}

	return false
}

// SetNamespace gets a reference to the given string and assigns it to the Namespace field.
func (o *SearchRequest) SetNamespace(v string) {
	o.Namespace = &v
}

// GetNextToken returns the NextToken field value if set, zero value otherwise.
func (o *SearchRequest) GetNextToken() string {
	if o == nil || o.NextToken == nil {
		var ret string
		return ret
	}
	return *o.NextToken
}

// GetNextTokenOk returns a tuple with the NextToken field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SearchRequest) GetNextTokenOk() (*string, bool) {
	if o == nil || o.NextToken == nil {
		return nil, false
	}
	return o.NextToken, true
}

// HasNextToken returns a boolean if a field has been set.
func (o *SearchRequest) HasNextToken() bool {
	if o != nil && o.NextToken != nil {
		return true
	}

	return false
}

// SetNextToken gets a reference to the given string and assigns it to the NextToken field.
func (o *SearchRequest) SetNextToken(v string) {
	o.NextToken = &v
}

// GetParams returns the Params field value if set, zero value otherwise.
func (o *SearchRequest) GetParams() map[string]string {
	if o == nil || o.Params == nil {
		var ret map[string]string
		return ret
	}
	return *o.Params
}

// GetParamsOk returns a tuple with the Params field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SearchRequest) GetParamsOk() (*map[string]string, bool) {
	if o == nil || o.Params == nil {
		return nil, false
	}
	return o.Params, true
}

// HasParams returns a boolean if a field has been set.
func (o *SearchRequest) HasParams() bool {
	if o != nil && o.Params != nil {
		return true
	}

	return false
}

// SetParams gets a reference to the given map[string]string and assigns it to the Params field.
func (o *SearchRequest) SetParams(v map[string]string) {
	o.Params = &v
}

// GetPerPage returns the PerPage field value if set, zero value otherwise.
func (o *SearchRequest) GetPerPage() int32 {
	if o == nil || o.PerPage == nil {
		var ret int32
		return ret
	}
	return *o.PerPage
}

// GetPerPageOk returns a tuple with the PerPage field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SearchRequest) GetPerPageOk() (*int32, bool) {
	if o == nil || o.PerPage == nil {
		return nil, false
	}
	return o.PerPage, true
}

// HasPerPage returns a boolean if a field has been set.
func (o *SearchRequest) HasPerPage() bool {
	if o != nil && o.PerPage != nil {
		return true
	}

	return false
}

// SetPerPage gets a reference to the given int32 and assigns it to the PerPage field.
func (o *SearchRequest) SetPerPage(v int32) {
	o.PerPage = &v
}

// GetPrefix returns the Prefix field value if set, zero value otherwise.
func (o *SearchRequest) GetPrefix() string {
	if o == nil || o.Prefix == nil {
		var ret string
		return ret
	}
	return *o.Prefix
}

// GetPrefixOk returns a tuple with the Prefix field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SearchRequest) GetPrefixOk() (*string, bool) {
	if o == nil || o.Prefix == nil {
		return nil, false
	}
	return o.Prefix, true
}

// HasPrefix returns a boolean if a field has been set.
func (o *SearchRequest) HasPrefix() bool {
	if o != nil && o.Prefix != nil {
		return true
	}

	return false
}

// SetPrefix gets a reference to the given string and assigns it to the Prefix field.
func (o *SearchRequest) SetPrefix(v string) {
	o.Prefix = &v
}

// GetRegion returns the Region field value if set, zero value otherwise.
func (o *SearchRequest) GetRegion() string {
	if o == nil || o.Region == nil {
		var ret string
		return ret
	}
	return *o.Region
}

// GetRegionOk returns a tuple with the Region field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SearchRequest) GetRegionOk() (*string, bool) {
	if o == nil || o.Region == nil {
		return nil, false
	}
	return o.Region, true
}

// HasRegion returns a boolean if a field has been set.
func (o *SearchRequest) HasRegion() bool {
	if o != nil && o.Region != nil {
		return true
	}

	return false
}

// SetRegion gets a reference to the given string and assigns it to the Region field.
func (o *SearchRequest) SetRegion(v string) {
	o.Region = &v
}

// GetWaitIndex returns the WaitIndex field value if set, zero value otherwise.
func (o *SearchRequest) GetWaitIndex() int32 {
	if o == nil || o.WaitIndex == nil {
		var ret int32
		return ret
	}
	return *o.WaitIndex
}

// GetWaitIndexOk returns a tuple with the WaitIndex field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SearchRequest) GetWaitIndexOk() (*int32, bool) {
	if o == nil || o.WaitIndex == nil {
		return nil, false
	}
	return o.WaitIndex, true
}

// HasWaitIndex returns a boolean if a field has been set.
func (o *SearchRequest) HasWaitIndex() bool {
	if o != nil && o.WaitIndex != nil {
		return true
	}

	return false
}

// SetWaitIndex gets a reference to the given int32 and assigns it to the WaitIndex field.
func (o *SearchRequest) SetWaitIndex(v int32) {
	o.WaitIndex = &v
}

// GetWaitTime returns the WaitTime field value if set, zero value otherwise.
func (o *SearchRequest) GetWaitTime() int64 {
	if o == nil || o.WaitTime == nil {
		var ret int64
		return ret
	}
	return *o.WaitTime
}

// GetWaitTimeOk returns a tuple with the WaitTime field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SearchRequest) GetWaitTimeOk() (*int64, bool) {
	if o == nil || o.WaitTime == nil {
		return nil, false
	}
	return o.WaitTime, true
}

// HasWaitTime returns a boolean if a field has been set.
func (o *SearchRequest) HasWaitTime() bool {
	if o != nil && o.WaitTime != nil {
		return true
	}

	return false
}

// SetWaitTime gets a reference to the given int64 and assigns it to the WaitTime field.
func (o *SearchRequest) SetWaitTime(v int64) {
	o.WaitTime = &v
}

func (o SearchRequest) MarshalJSON() ([]byte, error) {
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
	if o.WaitIndex != nil {
		toSerialize["Index"] = o.WaitIndex
	}
	if o.WaitTime != nil {
		toSerialize["Wait"] = o.WaitTime
	}
	return json.Marshal(toSerialize)
}

type NullableSearchRequest struct {
	value *SearchRequest
	isSet bool
}

func (v NullableSearchRequest) Get() *SearchRequest {
	return v.value
}

func (v *NullableSearchRequest) Set(val *SearchRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableSearchRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableSearchRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSearchRequest(val *SearchRequest) *NullableSearchRequest {
	return &NullableSearchRequest{value: val, isSet: true}
}

func (v NullableSearchRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSearchRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
