/**
 * Nomad
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 1.1.4
 * Contact: support@hashicorp.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 *
 */

import ApiClient from '../ApiClient';

/**
 * The DriverInfo model module.
 * @module model/DriverInfo
 * @version 1.1.4
 */
class DriverInfo {
    /**
     * Constructs a new <code>DriverInfo</code>.
     * @alias module:model/DriverInfo
     */
    constructor() { 
        
        DriverInfo.initialize(this);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj) { 
    }

    /**
     * Constructs a <code>DriverInfo</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:model/DriverInfo} obj Optional instance to populate.
     * @return {module:model/DriverInfo} The populated <code>DriverInfo</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new DriverInfo();

            if (data.hasOwnProperty('Attributes')) {
                obj['Attributes'] = ApiClient.convertToType(data['Attributes'], {'String': 'String'});
            }
            if (data.hasOwnProperty('Detected')) {
                obj['Detected'] = ApiClient.convertToType(data['Detected'], 'Boolean');
            }
            if (data.hasOwnProperty('HealthDescription')) {
                obj['HealthDescription'] = ApiClient.convertToType(data['HealthDescription'], 'String');
            }
            if (data.hasOwnProperty('Healthy')) {
                obj['Healthy'] = ApiClient.convertToType(data['Healthy'], 'Boolean');
            }
            if (data.hasOwnProperty('UpdateTime')) {
                obj['UpdateTime'] = ApiClient.convertToType(data['UpdateTime'], 'Date');
            }
        }
        return obj;
    }


}

/**
 * @member {Object.<String, String>} Attributes
 */
DriverInfo.prototype['Attributes'] = undefined;

/**
 * @member {Boolean} Detected
 */
DriverInfo.prototype['Detected'] = undefined;

/**
 * @member {String} HealthDescription
 */
DriverInfo.prototype['HealthDescription'] = undefined;

/**
 * @member {Boolean} Healthy
 */
DriverInfo.prototype['Healthy'] = undefined;

/**
 * @member {Date} UpdateTime
 */
DriverInfo.prototype['UpdateTime'] = undefined;






export default DriverInfo;
