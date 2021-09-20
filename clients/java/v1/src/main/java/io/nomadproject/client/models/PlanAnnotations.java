/*
 * Nomad
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 1.1.4
 * Contact: support@hashicorp.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package io.nomadproject.client.models;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.nomadproject.client.models.AllocationListStub;
import io.nomadproject.client.models.DesiredUpdates;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * PlanAnnotations
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen")
public class PlanAnnotations {
  public static final String SERIALIZED_NAME_DESIRED_T_G_UPDATES = "DesiredTGUpdates";
  @SerializedName(SERIALIZED_NAME_DESIRED_T_G_UPDATES)
  private Map<String, DesiredUpdates> desiredTGUpdates = null;

  public static final String SERIALIZED_NAME_PREEMPTED_ALLOCS = "PreemptedAllocs";
  @SerializedName(SERIALIZED_NAME_PREEMPTED_ALLOCS)
  private List<AllocationListStub> preemptedAllocs = null;


  public PlanAnnotations desiredTGUpdates(Map<String, DesiredUpdates> desiredTGUpdates) {
    
    this.desiredTGUpdates = desiredTGUpdates;
    return this;
  }

  public PlanAnnotations putDesiredTGUpdatesItem(String key, DesiredUpdates desiredTGUpdatesItem) {
    if (this.desiredTGUpdates == null) {
      this.desiredTGUpdates = new HashMap<String, DesiredUpdates>();
    }
    this.desiredTGUpdates.put(key, desiredTGUpdatesItem);
    return this;
  }

   /**
   * Get desiredTGUpdates
   * @return desiredTGUpdates
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public Map<String, DesiredUpdates> getDesiredTGUpdates() {
    return desiredTGUpdates;
  }


  public void setDesiredTGUpdates(Map<String, DesiredUpdates> desiredTGUpdates) {
    this.desiredTGUpdates = desiredTGUpdates;
  }


  public PlanAnnotations preemptedAllocs(List<AllocationListStub> preemptedAllocs) {
    
    this.preemptedAllocs = preemptedAllocs;
    return this;
  }

  public PlanAnnotations addPreemptedAllocsItem(AllocationListStub preemptedAllocsItem) {
    if (this.preemptedAllocs == null) {
      this.preemptedAllocs = new ArrayList<AllocationListStub>();
    }
    this.preemptedAllocs.add(preemptedAllocsItem);
    return this;
  }

   /**
   * Get preemptedAllocs
   * @return preemptedAllocs
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public List<AllocationListStub> getPreemptedAllocs() {
    return preemptedAllocs;
  }


  public void setPreemptedAllocs(List<AllocationListStub> preemptedAllocs) {
    this.preemptedAllocs = preemptedAllocs;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    PlanAnnotations planAnnotations = (PlanAnnotations) o;
    return Objects.equals(this.desiredTGUpdates, planAnnotations.desiredTGUpdates) &&
        Objects.equals(this.preemptedAllocs, planAnnotations.preemptedAllocs);
  }

  @Override
  public int hashCode() {
    return Objects.hash(desiredTGUpdates, preemptedAllocs);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class PlanAnnotations {\n");
    sb.append("    desiredTGUpdates: ").append(toIndentedString(desiredTGUpdates)).append("\n");
    sb.append("    preemptedAllocs: ").append(toIndentedString(preemptedAllocs)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}
