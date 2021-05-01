# brain-iot-sensiNact

Creates a distribution of sensiNact packaged in one single OSGi bundle, based on the Eclipse sensiNact's official repository. <br/>
It embeds : 
 * the sensiNact core modules;
 * the sensiNact application modules;
 * as well as the MQTT, HTTP and TTN southbound bridges. 

<i>Security modules of sensiNact are not embedded; the `mock-signature-validator` extra module, also integrated to the built bundle, overwrites the bundles' signature validation process of sensiNact.</i>
