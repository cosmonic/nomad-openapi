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
 * The FuzzyMatch model module.
 * @module model/FuzzyMatch
 * @version 1.1.4
 */
class FuzzyMatch {
    /**
     * Constructs a new <code>FuzzyMatch</code>.
     * @alias module:model/FuzzyMatch
     */
    constructor() { 
        
        FuzzyMatch.initialize(this);
    }

    /**
     * Initializes the fields of this object.
     * This method is used by the constructors of any subclasses, in order to implement multiple inheritance (mix-ins).
     * Only for internal use.
     */
    static initialize(obj) { 
    }

    /**
     * Constructs a <code>FuzzyMatch</code> from a plain JavaScript object, optionally creating a new instance.
     * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
     * @param {Object} data The plain JavaScript object bearing properties of interest.
     * @param {module:model/FuzzyMatch} obj Optional instance to populate.
     * @return {module:model/FuzzyMatch} The populated <code>FuzzyMatch</code> instance.
     */
    static constructFromObject(data, obj) {
        if (data) {
            obj = obj || new FuzzyMatch();

            if (data.hasOwnProperty('ID')) {
                obj['ID'] = ApiClient.convertToType(data['ID'], 'String');
            }
            if (data.hasOwnProperty('Scope')) {
                obj['Scope'] = ApiClient.convertToType(data['Scope'], ['String']);
            }
        }
        return obj;
    }


}

/**
 * @member {String} ID
 */
FuzzyMatch.prototype['ID'] = undefined;

/**
 * @member {Array.<String>} Scope
 */
FuzzyMatch.prototype['Scope'] = undefined;






export default FuzzyMatch;
