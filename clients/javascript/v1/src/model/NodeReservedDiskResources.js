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
 * The NodeReservedDiskResources model module.
 * @module model/NodeReservedDiskResources
 * @version 1.1.4
 */
class NodeReservedDiskResources {
    /**
     * Constructs a new <code>NodeReservedDiskResources</code>.
     * @alias module:model/NodeReservedDiskResources
     */
    constructor() { 
        
        NodeReservedDiskResources.initialize(this);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj) { 
    }

    /**
     * Constructs a <code>NodeReservedDiskResources</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:model/NodeReservedDiskResources} obj Optional instance to populate.
     * @return {module:model/NodeReservedDiskResources} The populated <code>NodeReservedDiskResources</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new NodeReservedDiskResources();

            if (data.hasOwnProperty('DiskMB')) {
                obj['DiskMB'] = ApiClient.convertToType(data['DiskMB'], 'Number');
            }
        }
        return obj;
    }


}

/**
 * @member {Number} DiskMB
 */
NodeReservedDiskResources.prototype['DiskMB'] = undefined;






export default NodeReservedDiskResources;
