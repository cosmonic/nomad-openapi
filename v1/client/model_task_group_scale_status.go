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

// TaskGroupScaleStatus struct for TaskGroupScaleStatus
type TaskGroupScaleStatus struct {
	Desired *int32 `json:"Desired,omitempty"`
	Events *[]ScalingEvent `json:"Events,omitempty"`
	Healthy *int32 `json:"Healthy,omitempty"`
	Placed *int32 `json:"Placed,omitempty"`
	Running *int32 `json:"Running,omitempty"`
	Unhealthy *int32 `json:"Unhealthy,omitempty"`
}

// NewTaskGroupScaleStatus instantiates a new TaskGroupScaleStatus object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewTaskGroupScaleStatus() *TaskGroupScaleStatus {
	this := TaskGroupScaleStatus{}
	return &this
}

// NewTaskGroupScaleStatusWithDefaults instantiates a new TaskGroupScaleStatus object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewTaskGroupScaleStatusWithDefaults() *TaskGroupScaleStatus {
	this := TaskGroupScaleStatus{}
	return &this
}

// GetDesired returns the Desired field value if set, zero value otherwise.
func (o *TaskGroupScaleStatus) GetDesired() int32 {
	if o == nil || o.Desired == nil {
		var ret int32
		return ret
	}
	return *o.Desired
}

// GetDesiredOk returns a tuple with the Desired field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TaskGroupScaleStatus) GetDesiredOk() (*int32, bool) {
	if o == nil || o.Desired == nil {
		return nil, false
	}
	return o.Desired, true
}

// HasDesired returns a boolean if a field has been set.
func (o *TaskGroupScaleStatus) HasDesired() bool {
	if o != nil && o.Desired != nil {
		return true
	}

	return false
}

// SetDesired gets a reference to the given int32 and assigns it to the Desired field.
func (o *TaskGroupScaleStatus) SetDesired(v int32) {
	o.Desired = &v
}

// GetEvents returns the Events field value if set, zero value otherwise.
func (o *TaskGroupScaleStatus) GetEvents() []ScalingEvent {
	if o == nil || o.Events == nil {
		var ret []ScalingEvent
		return ret
	}
	return *o.Events
}

// GetEventsOk returns a tuple with the Events field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TaskGroupScaleStatus) GetEventsOk() (*[]ScalingEvent, bool) {
	if o == nil || o.Events == nil {
		return nil, false
	}
	return o.Events, true
}

// HasEvents returns a boolean if a field has been set.
func (o *TaskGroupScaleStatus) HasEvents() bool {
	if o != nil && o.Events != nil {
		return true
	}

	return false
}

// SetEvents gets a reference to the given []ScalingEvent and assigns it to the Events field.
func (o *TaskGroupScaleStatus) SetEvents(v []ScalingEvent) {
	o.Events = &v
}

// GetHealthy returns the Healthy field value if set, zero value otherwise.
func (o *TaskGroupScaleStatus) GetHealthy() int32 {
	if o == nil || o.Healthy == nil {
		var ret int32
		return ret
	}
	return *o.Healthy
}

// GetHealthyOk returns a tuple with the Healthy field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TaskGroupScaleStatus) GetHealthyOk() (*int32, bool) {
	if o == nil || o.Healthy == nil {
		return nil, false
	}
	return o.Healthy, true
}

// HasHealthy returns a boolean if a field has been set.
func (o *TaskGroupScaleStatus) HasHealthy() bool {
	if o != nil && o.Healthy != nil {
		return true
	}

	return false
}

// SetHealthy gets a reference to the given int32 and assigns it to the Healthy field.
func (o *TaskGroupScaleStatus) SetHealthy(v int32) {
	o.Healthy = &v
}

// GetPlaced returns the Placed field value if set, zero value otherwise.
func (o *TaskGroupScaleStatus) GetPlaced() int32 {
	if o == nil || o.Placed == nil {
		var ret int32
		return ret
	}
	return *o.Placed
}

// GetPlacedOk returns a tuple with the Placed field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TaskGroupScaleStatus) GetPlacedOk() (*int32, bool) {
	if o == nil || o.Placed == nil {
		return nil, false
	}
	return o.Placed, true
}

// HasPlaced returns a boolean if a field has been set.
func (o *TaskGroupScaleStatus) HasPlaced() bool {
	if o != nil && o.Placed != nil {
		return true
	}

	return false
}

// SetPlaced gets a reference to the given int32 and assigns it to the Placed field.
func (o *TaskGroupScaleStatus) SetPlaced(v int32) {
	o.Placed = &v
}

// GetRunning returns the Running field value if set, zero value otherwise.
func (o *TaskGroupScaleStatus) GetRunning() int32 {
	if o == nil || o.Running == nil {
		var ret int32
		return ret
	}
	return *o.Running
}

// GetRunningOk returns a tuple with the Running field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TaskGroupScaleStatus) GetRunningOk() (*int32, bool) {
	if o == nil || o.Running == nil {
		return nil, false
	}
	return o.Running, true
}

// HasRunning returns a boolean if a field has been set.
func (o *TaskGroupScaleStatus) HasRunning() bool {
	if o != nil && o.Running != nil {
		return true
	}

	return false
}

// SetRunning gets a reference to the given int32 and assigns it to the Running field.
func (o *TaskGroupScaleStatus) SetRunning(v int32) {
	o.Running = &v
}

// GetUnhealthy returns the Unhealthy field value if set, zero value otherwise.
func (o *TaskGroupScaleStatus) GetUnhealthy() int32 {
	if o == nil || o.Unhealthy == nil {
		var ret int32
		return ret
	}
	return *o.Unhealthy
}

// GetUnhealthyOk returns a tuple with the Unhealthy field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TaskGroupScaleStatus) GetUnhealthyOk() (*int32, bool) {
	if o == nil || o.Unhealthy == nil {
		return nil, false
	}
	return o.Unhealthy, true
}

// HasUnhealthy returns a boolean if a field has been set.
func (o *TaskGroupScaleStatus) HasUnhealthy() bool {
	if o != nil && o.Unhealthy != nil {
		return true
	}

	return false
}

// SetUnhealthy gets a reference to the given int32 and assigns it to the Unhealthy field.
func (o *TaskGroupScaleStatus) SetUnhealthy(v int32) {
	o.Unhealthy = &v
}

func (o TaskGroupScaleStatus) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Desired != nil {
		toSerialize["Desired"] = o.Desired
	}
	if o.Events != nil {
		toSerialize["Events"] = o.Events
	}
	if o.Healthy != nil {
		toSerialize["Healthy"] = o.Healthy
	}
	if o.Placed != nil {
		toSerialize["Placed"] = o.Placed
	}
	if o.Running != nil {
		toSerialize["Running"] = o.Running
	}
	if o.Unhealthy != nil {
		toSerialize["Unhealthy"] = o.Unhealthy
	}
	return json.Marshal(toSerialize)
}

type NullableTaskGroupScaleStatus struct {
	value *TaskGroupScaleStatus
	isSet bool
}

func (v NullableTaskGroupScaleStatus) Get() *TaskGroupScaleStatus {
	return v.value
}

func (v *NullableTaskGroupScaleStatus) Set(val *TaskGroupScaleStatus) {
	v.value = val
	v.isSet = true
}

func (v NullableTaskGroupScaleStatus) IsSet() bool {
	return v.isSet
}

func (v *NullableTaskGroupScaleStatus) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableTaskGroupScaleStatus(val *TaskGroupScaleStatus) *NullableTaskGroupScaleStatus {
	return &NullableTaskGroupScaleStatus{value: val, isSet: true}
}

func (v NullableTaskGroupScaleStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableTaskGroupScaleStatus) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


