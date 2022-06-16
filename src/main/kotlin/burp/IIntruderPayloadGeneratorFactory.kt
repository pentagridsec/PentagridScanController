package burp

/*
 * @(#)IIntruderPayloadGeneratorFactory.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * Extensions can implement this interface and then call
 * `IBurpExtenderCallbacks.registerIntruderPayloadGeneratorFactory()`
 * to register a factory for custom Intruder payloads.
 */
interface IIntruderPayloadGeneratorFactory {
    /**
     * This method is used by Burp to obtain the name of the payload generator.
     * This will be displayed as an option within the Intruder UI when the user
     * selects to use extension-generated payloads.
     *
     * @return The name of the payload generator.
     */
    val generatorName: String

    /**
     * This method is used by Burp when the user starts an Intruder attack that
     * uses this payload generator.
     *
     * @param attack An
     * `IIntruderAttack` object that can be queried to obtain details
     * about the attack in which the payload generator will be used.
     * @return A new instance of
     * `IIntruderPayloadGenerator` that will be used to generate
     * payloads for the attack.
     */
    fun createNewInstance(attack: IIntruderAttack): IIntruderPayloadGenerator
}
