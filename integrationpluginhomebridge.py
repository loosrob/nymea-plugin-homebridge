import nymea
import time
import threading
import json
import requests
import random
from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, Zeroconf
from typing import Callable, List

class ZeroconfDevice(object):
    # To do: replace with nymea serviceBrowser
    def __init__(self, name: str, ip: str, port: int, model: str, id: str) -> None:
        self.name = name
        self.ip = ip
        self.port = port
        self.model = model
        self.id = id

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.__dict__})"

    def __eq__(self, other) -> bool:
        return self is other or self.__dict__ == other.__dict__

class ZeroconfListener(object):
    # To do: replace with nymea serviceBrowser
    """Basic zeroconf listener."""

    def __init__(self, func: Callable[[ServiceInfo], None]) -> None:
        """Initialize zeroconf listener with function callback."""
        self._func = func

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.__dict__})"

    def __eq__(self, other) -> bool:
        return self is other or self.__dict__ == other.__dict__

    def add_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
        """Callback function when zeroconf service is discovered."""
        self._func(zeroconf.get_service_info(type, name))

    def update_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
        return

discoveredIps = None
pollTimer = None

def init():
    global discoveredIps
    discoveredIps = findIps()
    logger.log("Init discoveredIps", discoveredIps)

def startPairing(info):
    info.finish(nymea.ThingErrorNoError, "Please enter the login credentials for your Homebridge gateway.")

def confirmPairing(info, username, secret):
    logger.log("Confirming pairing for", info.thingName, info)
    searchSystemId = info.paramValue(gatewayThingSystemIdParamTypeId)
    for i in range(0, len(discoveredIps)):
        systemId = discoveredIps[i][2]
        if systemId == searchSystemId:
            deviceIp = discoveredIps[i][0]
    loginState, token, tokentype = getToken(info.thingId, deviceIp, username, secret)
    if loginState == True:
        info.finish(nymea.ThingErrorNoError)
    else:
        info.finish(nymea.ThingErrorAuthenticationFailure, "Error logging in!")

def checkToken(gateway, deviceIp):
    # obtain login info & current token for gateway
    pluginStorage().beginGroup(gateway.id)
    username = pluginStorage().value("username")
    secret = pluginStorage().value("password")
    token = pluginStorage().value("token")
    tokentype = pluginStorage().value("tokentype")
    pluginStorage().endGroup()
    if deviceIp == None:
        deviceIp = gateway.stateValue(gatewayUrlStateTypeId)
    
    # check token validity
    logger.log("Checking token validity")
    authheader = tokentype + ' ' + token
    headers = {'Authorization': authheader, 'Accept': '*/*'}
    rUrl = 'http://' + deviceIp + ':8581/api/auth/check'
    rr = requests.get(rUrl, headers=headers)
    logger.log("token check, status code: " + str(rr.status_code))
    if rr.status_code == 401:
        # token expired, so we will renew it
        logger.log("Token expired, renewing")
        loginState, token, tokentype = getToken(gateway.id, deviceIp, username, secret)
    elif rr.status_code == requests.codes.ok:
        # token still valid
        logger.log("Token still valid")
        loginState = True
    else:
        logger.log("Other state?")
        loginState = False
    return loginState, token, tokentype

def getToken(gatewayId, deviceIp, username, secret):
    rUrl = 'http://' + deviceIp + ':8581/api/auth/login'
    headers = {'Content-Type': 'application/json', 'Accept': '*/*'}
    body = '{"username":"' + username + '","password":"' + secret + '","otp":"string"}'
    rr = requests.post(rUrl, headers=headers, data=body)
    if rr.status_code == 201:
        loginState = True
        responseJson = rr.json()
        token = responseJson['access_token']
        tokentype = responseJson['token_type']
        validity = int(responseJson['expires_in'])
        pluginStorage().beginGroup(gatewayId)
        pluginStorage().setValue("username", username)
        pluginStorage().setValue("password", secret)
        pluginStorage().setValue("token", token)
        pluginStorage().setValue("tokentype", tokentype)
        pluginStorage().endGroup()
    else:
        loginState = False
        token = None
        tokentype = None
    return loginState, token, tokentype

def setupThing(info):
    if info.thing.thingClassId == gatewayThingClassId:
        searchSystemId = info.thing.paramValue(gatewayThingSystemIdParamTypeId)
        logger.log("setupThing called for", info.thing.name, searchSystemId)
        deviceIp = None
        for i in range(0, len(discoveredIps)):
            systemId = discoveredIps[i][2]
            if systemId == searchSystemId:
                deviceIp = discoveredIps[i][0]
        if deviceIp != None:
            info.thing.setStateValue(gatewayUrlStateTypeId, deviceIp)
            info.thing.setStateValue(gatewayConnectedStateTypeId, True)
            loginState, token, tokentype = checkToken(info.thing, deviceIp)
            if loginState == True:
                info.thing.setStateValue(gatewayLoggedInStateTypeId, True)
                pollGateway(info.thing)
                info.finish(nymea.ThingErrorNoError)
            else:
                info.thing.setStateValue(gatewayLoggedInStateTypeId, False)
                info.finish(nymea.ThingErrorHardwareFailure, "Error logging in to the device on the network.")
        else:
            info.thing.setStateValue(gatewayConnectedStateTypeId, False)
            info.thing.setStateValue(gatewayLoggedInStateTypeId, False)
            info.finish(nymea.ThingErrorHardwareFailure, "Could not find the device on the network.")

        # If no poll timer is set up yet, start it now
        logger.log("Creating polltimer")
        global pollTimer
        pollTimer = threading.Timer(10, pollService)
        pollTimer.start()
        
        info.finish(nymea.ThingErrorNoError)
        return

    # Setup for the devices
    if info.thing.thingClassId == deviceThingClassId:
        pollGateway(info.thing)
        info.finish(nymea.ThingErrorNoError)
        return

def discoverThings(info):
    if info.thingClassId == gatewayThingClassId:
        logger.log("Discovery started for", info.thingClassId)
        for i in range(0, len(discoveredIps)):
            deviceIp = discoveredIps[i][0]
            deviceName = discoveredIps[i][1]
            systemId = discoveredIps[i][2]
            rUrl = 'http://' + deviceIp + ':8581/api/auth/check'
            # We abuse the url to check if a token is still valid to check if the device can be a homebridge gateway
            headers = {'Accept': '*/*'}
            rr = requests.get(rUrl, headers=headers)
            pollResponse = rr.text
            if rr.status_code != 404:
                logger.log("Device with IP " + deviceIp + " seems to be a Homebridge gateway.")
                # check if device already known
                exists = False
                for possibleGateway in myThings():
                    logger.log("Comparing to existing gateways: is %s a gateway?" % (possibleGateway.name))
                    if possibleGateway.thingClassId == gatewayThingClassId:
                        logger.log("Yes, %s is a gateway." % (possibleGateway.name))
                        if possibleGateway.paramValue(gatewayThingSystemIdParamTypeId) == systemId:
                            logger.log("Already have gateway with system ID %s in the system: %s" % (systemId, possibleGateway.name))
                            foundGateway = possibleGateway
                            exists = True
                        else:
                            logger.log("Thing %s doesn't match with found gateway with system ID %s" % (possibleGateway.name, systemId))
                if exists == False: # Gateway doesn't exist yet, so add it
                    thingDescriptor = nymea.ThingDescriptor(gatewayThingClassId, deviceName)
                    thingDescriptor.params = [
                        nymea.Param(gatewayThingSystemIdParamTypeId, systemId)
                    ]
                    info.addDescriptor(thingDescriptor)
                else: # Gateway already exists, so show it to allow reconfiguration
                    thingDescriptor = nymea.ThingDescriptor(gatewayThingClassId, deviceName, thingId=foundGateway.id)
                    thingDescriptor.params = [
                        nymea.Param(gatewayThingSystemIdParamTypeId, systemId)
                    ]
                    info.addDescriptor(thingDescriptor)
            else:
                logger.log("Device with IP " + deviceIp + " does not appear to be a Homebridge Gateway.")
        info.finish(nymea.ThingErrorNoError)
        return

    if info.thingClassId == deviceThingClassId:
        logger.log("Discovery started for", info.thingClassId)

        for possibleGateway in myThings():
            logger.log("Looking for existing gateways to add devices: is %s a gateway?" % (possibleGateway.name))
            if possibleGateway.thingClassId == gatewayThingClassId:
                gateway = possibleGateway
                deviceIp = gateway.stateValue(gatewayUrlStateTypeId)
                logger.log("Yes, %s with IP address %s is a gateway, looking for devices." % (gateway.name, deviceIp))
                #pluginStorage().beginGroup(gateway.id)
                #username = pluginStorage().value("username")
                #secret = pluginStorage().value("password")
                #token = pluginStorage().value("token")
                #tokentype = pluginStorage().value("tokentype")
                #pluginStorage().endGroup()
                loginState, token, tokentype = checkToken(gateway, deviceIp)
                if loginState == True:
                    rUrl = 'http://' + deviceIp + ':8581/api/accessories'
                    authheader = tokentype + ' ' + token
                    headers = {'Authorization': authheader, 'Accept': '*/*'}
                    rr = requests.get(rUrl, headers=headers)
                    responseJson = rr.json()
                    for i in range(0, len(responseJson)): 
                        # get possibleDevices from rr.json() and loop through them
                        serviceCharacteristics = responseJson[i]['serviceCharacteristics']
                        powerFound = False
                        for j in range(0, len(serviceCharacteristics)):  
                            charType = serviceCharacteristics[j]['type']
                            if charType == "Active":
                                powerFound = True
                        if powerFound == True:
                            deviceType = responseJson[i]['humanType']
                            deviceName = responseJson[i]['serviceName']
                            deviceId = responseJson[i]['uniqueId']
                            # check if device exists
                            exists = False
                            for possibleDevice in myThings():
                                logger.log("Comparing to existing devices: is %s a device?" % (possibleDevice.name))
                                if possibleDevice.thingClassId == deviceThingClassId:
                                    logger.log("Yes, %s is a device." % (possibleDevice.name))
                                    if possibleDevice.paramValue(deviceThingDeviceIdParamTypeId) == deviceId:
                                        logger.log("Already have device with device ID %s in the system: %s" % (deviceId, possibleDevice.name))
                                        foundDevice = possibleDevice
                                        exists = True
                                    else:
                                        logger.log("Thing %s doesn't match with found device with device ID %s" % (possibleDevice.name, deviceId))
                            if exists == False: # Gateway doesn't exist yet, so add it
                                thingDescriptor = nymea.ThingDescriptor(deviceThingClassId, deviceName, parentId=gateway.id)
                                thingDescriptor.params = [
                                    nymea.Param(deviceThingDeviceIdParamTypeId, deviceId),
                                    nymea.Param(deviceThingTypeParamTypeId, deviceType)
                                ]
                                info.addDescriptor(thingDescriptor)
                            else: # Gateway already exists, so show it to allow reconfiguration
                                thingDescriptor = nymea.ThingDescriptor(deviceThingClassId, deviceName, thingId=foundDevice.id, parentId=gateway.id)
                                thingDescriptor.params = [
                                    nymea.Param(deviceThingDeviceIdParamTypeId, deviceId),
                                    nymea.Param(deviceThingTypeParamTypeId, deviceType)
                                ]
                                info.addDescriptor(thingDescriptor)
                    #end for loop here
                    info.finish(nymea.ThingErrorNoError)
                else:
                    logger.log("Gateway loggin error: can't discover devices!")
                    info.finish(nymea.ThingErrorHardwareFailure, "Error logging in to the device on the network.")
        return

def findIps():
    # we use zeroconf (def discover & classes ZeroconfDevice & ZeroconfListener) as borrowed from pyvizio
    ipList = discover("_hap._tcp.local.", 5)
    discoveredIps = []
    for i in range(0, len(ipList)):
        deviceInfo = ipList[i]
        if "Homebridge" in deviceInfo.name:
            stringIndex = deviceInfo.name.find(".local")
            deviceName = deviceInfo.name[0:stringIndex]
            systemId = getSystemId(deviceName)
            discoveredIps.append([deviceInfo.ip, deviceName, systemId])
    return discoveredIps
    
def discover(service_type: str, timeout: int = 5) -> List[ZeroconfDevice]:
    # To do: replace with nymea serviceBrowser
    """From pyvizio: Return all discovered zeroconf services of a given service type over given timeout period."""
    services = []

    def append_service(info: ServiceInfo) -> None:
        """Append discovered zeroconf service to service list."""
        name = info.name[: -(len(info.type) + 1)]
        ip = info.parsed_addresses(IPVersion.V4Only)[0]
        port = info.port
        model = info.properties.get(b"name", "")
        id = info.properties.get(b"id")

        # handle id decode for various discovered use cases
        if isinstance(id, bytes):
            try:
                int(id, 16)
            except Exception:
                id = id.hex()
        else:
            id = None

        service = ZeroconfDevice(name, ip, port, model, id)
        services.append(service)

    zeroconf = Zeroconf()
    ServiceBrowser(zeroconf, service_type, ZeroconfListener(append_service))
    time.sleep(timeout)
    zeroconf.close()

    return services

def getSystemId(deviceName):
    stringIndex = deviceName.find("Homebridge")
    stringLen = len("Homebridge")
    systemId = deviceName[stringIndex+stringLen:]
    stringIndex = systemId.find(" ")
    if stringIndex == 0:
        systemId = systemId[1:]
    return systemId

def pollGateway(thing):
    if thing.thingClassId == gatewayThingClassId:
        logger.log("polling gateway", thing.name)
        deviceIp = thing.stateValue(gatewayUrlStateTypeId)
        #pluginStorage().beginGroup(thing.id)
        #username = pluginStorage().value("username")
        #secret = pluginStorage().value("password")
        #token = pluginStorage().value("token")
        #tokentype = pluginStorage().value("tokentype")
        #pluginStorage().endGroup()
        loginState, token, tokentype = checkToken(thing, deviceIp)
        if loginState == True:
            thing.setStateValue(gatewayLoggedInStateTypeId, True)
        else:
            thing.setStateValue(gatewayLoggedInStateTypeId, False)
        # also set gatewayConnectedStateTypeId? based on which criteria?
    elif thing.thingClassId == deviceThingClassId:
        logger.log("polling device", thing.name)
        # get parent gateway thing, needed to get gateway query response
        for possibleParent in myThings():
            if possibleParent.id == thing.parentId:
                parentGateway = possibleParent
        if parentGateway.stateValue(gatewayLoggedInStateTypeId) == True:
            #thing.setStateValue(deviceConnectedStateTypeId, True)
            deviceIp = parentGateway.stateValue(gatewayUrlStateTypeId)
            #pluginStorage().beginGroup(parentGateway.id)
            #token = pluginStorage().value("token")
            #tokentype = pluginStorage().value("tokentype")
            #pluginStorage().endGroup()
            loginState, token, tokentype = checkToken(parentGateway, deviceIp)
            if loginState == True:
                thing.setStateValue(deviceConnectedStateTypeId, True)
                deviceId = thing.paramValue(deviceThingDeviceIdParamTypeId)
                rUrl = 'http://' + deviceIp + ':8581/api/accessories/' + deviceId
                authheader = tokentype + ' ' + token
                headers = {'Authorization': authheader, 'Accept': '*/*'}
                rr = requests.get(rUrl, headers=headers)
                responseJson = rr.json()
                serviceCharacteristics = responseJson['serviceCharacteristics']
                for i in range(0, len(serviceCharacteristics)):
                    if serviceCharacteristics[i]['type'] == 'Active':
                        power = int(serviceCharacteristics[i]['value'])
                        thing.setStateValue(devicePowerStateTypeId, power)
            else:
                thing.setStateValue(deviceConnectedStateTypeId, False)
        else:
            thing.setStateValue(deviceConnectedStateTypeId, False)

def pollService():
    logger.log("pollService!!!")
    # while polling: check if token still valid, if not: renew? or only as try/except?
    for thing in myThings():
        if thing.thingClassId == gatewayThingClassId or thing.thingClassId == deviceThingClassId:
            pollGateway(thing)
    # restart the timer for next poll (if player is playing, increase poll frequency)
    global pollTimer
    pollTimer = threading.Timer(30, pollService)
    pollTimer.start()

def executeAction(info):
    if info.thing.thingClassId == deviceThingClassId:
        # get parent gateway thing, needed to get deviceIp
        for possibleParent in myThings():
            if possibleParent.id == info.thing.parentId:
                parentGateway = possibleParent
        deviceIp = parentGateway.stateValue(gatewayUrlStateTypeId)
        deviceId = info.thing.paramValue(deviceThingDeviceIdParamTypeId)
    # no actions implemented for gateway
    # elif info.thing.thingClassId == gatewayThingClassId:
    #     deviceIp = info.thing.stateValue(gatewayUrlStateTypeId)
    pollGateway(parentGateway)
    pollGateway(info.thing)
    logger.log("executeAction called for thing", info.thing.name, deviceIp, info.actionTypeId, info.params)

    if info.actionTypeId == devicePowerActionTypeId:
        if parentGateway.stateValue(gatewayLoggedInStateTypeId) == True:
            if info.paramValue(devicePowerActionPowerParamTypeId) == True:
                power = 1
            else:
                power = 0
            #pluginStorage().beginGroup(parentGateway.id)
            #token = pluginStorage().value("token")
            #tokentype = pluginStorage().value("tokentype")
            #pluginStorage().endGroup()
            loginState, token, tokentype = checkToken(parentGateway, deviceIp)
            deviceId = info.thing.paramValue(deviceThingDeviceIdParamTypeId)
            rUrl = 'http://' + deviceIp + ':8581/api/accessories/' + deviceId
            authheader = tokentype + ' ' + token
            headers = {'Authorization': authheader, 'Accept': '*/*', 'Content-type': 'application/json'}
            body = '{"characteristicType":"Active","value":' + str(power) + '}'
            rr = requests.put(rUrl, headers=headers, data=body)
            pollGateway(info.thing)
            if rr.status_code == 200:
                logger.log("Power changed")
                info.finish(nymea.ThingErrorNoError)
            else:
                logger.log("Power not changed")
                info.finish(nymea.ThingErrorHardwareFailure, "Device power could not be set.")
            return
        else:
            info.finish(nymea.ThingErrorHardwareFailure, "Device power could not be set, gateway login not OK.")
    else:
        logger.log("Action not yet implemented for thing")
        info.finish(nymea.ThingErrorNoError)
        return
    
def deinit():
    global pollTimer
    # If we started a poll timer, cancel it on shutdown.
    if pollTimer is not None:
        pollTimer.cancel()

def thingRemoved(thing):
    logger.log("removeThing called for", thing.name)
    # Clean up all data related to this thing
    if pollTimer is not None:
        pollTimer.cancel()