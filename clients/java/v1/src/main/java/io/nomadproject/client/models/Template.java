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
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;

/**
 * Template
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen")
public class Template {
  public static final String SERIALIZED_NAME_CHANGE_MODE = "ChangeMode";
  @SerializedName(SERIALIZED_NAME_CHANGE_MODE)
  private String changeMode;

  public static final String SERIALIZED_NAME_CHANGE_SIGNAL = "ChangeSignal";
  @SerializedName(SERIALIZED_NAME_CHANGE_SIGNAL)
  private String changeSignal;

  public static final String SERIALIZED_NAME_DEST_PATH = "DestPath";
  @SerializedName(SERIALIZED_NAME_DEST_PATH)
  private String destPath;

  public static final String SERIALIZED_NAME_EMBEDDED_TMPL = "EmbeddedTmpl";
  @SerializedName(SERIALIZED_NAME_EMBEDDED_TMPL)
  private String embeddedTmpl;

  public static final String SERIALIZED_NAME_ENVVARS = "Envvars";
  @SerializedName(SERIALIZED_NAME_ENVVARS)
  private Boolean envvars;

  public static final String SERIALIZED_NAME_LEFT_DELIM = "LeftDelim";
  @SerializedName(SERIALIZED_NAME_LEFT_DELIM)
  private String leftDelim;

  public static final String SERIALIZED_NAME_PERMS = "Perms";
  @SerializedName(SERIALIZED_NAME_PERMS)
  private String perms;

  public static final String SERIALIZED_NAME_RIGHT_DELIM = "RightDelim";
  @SerializedName(SERIALIZED_NAME_RIGHT_DELIM)
  private String rightDelim;

  public static final String SERIALIZED_NAME_SOURCE_PATH = "SourcePath";
  @SerializedName(SERIALIZED_NAME_SOURCE_PATH)
  private String sourcePath;

  public static final String SERIALIZED_NAME_SPLAY = "Splay";
  @SerializedName(SERIALIZED_NAME_SPLAY)
  private Long splay;

  public static final String SERIALIZED_NAME_VAULT_GRACE = "VaultGrace";
  @SerializedName(SERIALIZED_NAME_VAULT_GRACE)
  private Long vaultGrace;


  public Template changeMode(String changeMode) {
    
    this.changeMode = changeMode;
    return this;
  }

   /**
   * Get changeMode
   * @return changeMode
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getChangeMode() {
    return changeMode;
  }


  public void setChangeMode(String changeMode) {
    this.changeMode = changeMode;
  }


  public Template changeSignal(String changeSignal) {
    
    this.changeSignal = changeSignal;
    return this;
  }

   /**
   * Get changeSignal
   * @return changeSignal
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getChangeSignal() {
    return changeSignal;
  }


  public void setChangeSignal(String changeSignal) {
    this.changeSignal = changeSignal;
  }


  public Template destPath(String destPath) {
    
    this.destPath = destPath;
    return this;
  }

   /**
   * Get destPath
   * @return destPath
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getDestPath() {
    return destPath;
  }


  public void setDestPath(String destPath) {
    this.destPath = destPath;
  }


  public Template embeddedTmpl(String embeddedTmpl) {
    
    this.embeddedTmpl = embeddedTmpl;
    return this;
  }

   /**
   * Get embeddedTmpl
   * @return embeddedTmpl
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getEmbeddedTmpl() {
    return embeddedTmpl;
  }


  public void setEmbeddedTmpl(String embeddedTmpl) {
    this.embeddedTmpl = embeddedTmpl;
  }


  public Template envvars(Boolean envvars) {
    
    this.envvars = envvars;
    return this;
  }

   /**
   * Get envvars
   * @return envvars
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public Boolean getEnvvars() {
    return envvars;
  }


  public void setEnvvars(Boolean envvars) {
    this.envvars = envvars;
  }


  public Template leftDelim(String leftDelim) {
    
    this.leftDelim = leftDelim;
    return this;
  }

   /**
   * Get leftDelim
   * @return leftDelim
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getLeftDelim() {
    return leftDelim;
  }


  public void setLeftDelim(String leftDelim) {
    this.leftDelim = leftDelim;
  }


  public Template perms(String perms) {
    
    this.perms = perms;
    return this;
  }

   /**
   * Get perms
   * @return perms
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getPerms() {
    return perms;
  }


  public void setPerms(String perms) {
    this.perms = perms;
  }


  public Template rightDelim(String rightDelim) {
    
    this.rightDelim = rightDelim;
    return this;
  }

   /**
   * Get rightDelim
   * @return rightDelim
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getRightDelim() {
    return rightDelim;
  }


  public void setRightDelim(String rightDelim) {
    this.rightDelim = rightDelim;
  }


  public Template sourcePath(String sourcePath) {
    
    this.sourcePath = sourcePath;
    return this;
  }

   /**
   * Get sourcePath
   * @return sourcePath
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getSourcePath() {
    return sourcePath;
  }


  public void setSourcePath(String sourcePath) {
    this.sourcePath = sourcePath;
  }


  public Template splay(Long splay) {
    
    this.splay = splay;
    return this;
  }

   /**
   * Get splay
   * @return splay
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public Long getSplay() {
    return splay;
  }


  public void setSplay(Long splay) {
    this.splay = splay;
  }


  public Template vaultGrace(Long vaultGrace) {
    
    this.vaultGrace = vaultGrace;
    return this;
  }

   /**
   * Get vaultGrace
   * @return vaultGrace
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public Long getVaultGrace() {
    return vaultGrace;
  }


  public void setVaultGrace(Long vaultGrace) {
    this.vaultGrace = vaultGrace;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Template template = (Template) o;
    return Objects.equals(this.changeMode, template.changeMode) &&
        Objects.equals(this.changeSignal, template.changeSignal) &&
        Objects.equals(this.destPath, template.destPath) &&
        Objects.equals(this.embeddedTmpl, template.embeddedTmpl) &&
        Objects.equals(this.envvars, template.envvars) &&
        Objects.equals(this.leftDelim, template.leftDelim) &&
        Objects.equals(this.perms, template.perms) &&
        Objects.equals(this.rightDelim, template.rightDelim) &&
        Objects.equals(this.sourcePath, template.sourcePath) &&
        Objects.equals(this.splay, template.splay) &&
        Objects.equals(this.vaultGrace, template.vaultGrace);
  }

  @Override
  public int hashCode() {
    return Objects.hash(changeMode, changeSignal, destPath, embeddedTmpl, envvars, leftDelim, perms, rightDelim, sourcePath, splay, vaultGrace);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Template {\n");
    sb.append("    changeMode: ").append(toIndentedString(changeMode)).append("\n");
    sb.append("    changeSignal: ").append(toIndentedString(changeSignal)).append("\n");
    sb.append("    destPath: ").append(toIndentedString(destPath)).append("\n");
    sb.append("    embeddedTmpl: ").append(toIndentedString(embeddedTmpl)).append("\n");
    sb.append("    envvars: ").append(toIndentedString(envvars)).append("\n");
    sb.append("    leftDelim: ").append(toIndentedString(leftDelim)).append("\n");
    sb.append("    perms: ").append(toIndentedString(perms)).append("\n");
    sb.append("    rightDelim: ").append(toIndentedString(rightDelim)).append("\n");
    sb.append("    sourcePath: ").append(toIndentedString(sourcePath)).append("\n");
    sb.append("    splay: ").append(toIndentedString(splay)).append("\n");
    sb.append("    vaultGrace: ").append(toIndentedString(vaultGrace)).append("\n");
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

