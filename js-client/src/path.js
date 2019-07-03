
lnn.path = {}

/**
 * This function selects a lnn.path from the parsed consensus and parsed descriptors
 * Flavor is 'unflavored'
 * 
 * @param {Object} consensus a parsed consensus
 * @param {Object} descriptors parsed descriptors of the routers in the consensus
 * @param {Bool} isChutney boolean used to indicate if the lnn.path selection is done with routers from chutney
 */
lnn.path.select = function (consensus, descriptors, isChutney) {
    if(isChutney === undefined){
        lnn.path["isChutney"] = false
    }else{
        lnn.path["isChutney"] = isChutney
    }

    //build a hashmap of descriptor where the keys are the identity
    lnn.path["descriptorsMap"] = {}

    for (let descriptor of descriptors) {
        let identity = descriptor['router'].identity
        lnn.path.descriptorsMap[identity] = descriptor
    }

    //pre-process consensus by filering the routers that do not obey
    //the minimal constraints
    lnn.path["consensus"] = consensus['routers'].filter(r => lnn.path.obeyMinimalConstraints(r))
    
    //lnn.path selection
    lnn.path["exit"] = lnn.path.chooseGoodExit(consensus)
    lnn.path["guard"] = lnn.path.chooseGoodGuard(consensus)
    lnn.path["middle"] = lnn.path.chooseGoodMiddle(consensus)

    //TODO: it should create/return a new lnn.path and not the descriptors
    return [lnn.path.guard, lnn.path.middle, lnn.path.exit]
}

//assumes microdesc flavor.
lnn.path.select_end_path = function (consensus, descriptors,guard, isChutney, tcp_ports) {
    if(isChutney === undefined){
        lnn.path["isChutney"] = false
    }else{
        lnn.path["isChutney"] = isChutney
    }

    //build a hashmap of descriptor where the keys are the identity
    let consMap = {}
    for(let router of consensus['routers']) {
        consMap[router['micro-digest']] = router
    }

    lnn.path["descriptorsMap"] = {}

    for (let descriptor of descriptors) {
        descriptor['router'] = consMap[descriptor['micro-digest']]
        descriptor['bandwidth'] = {}
        descriptor['bandwidth']['avg'] = descriptor['router']['w']['Bandwidth']

        let identity = descriptor['router'].identity
        lnn.path.descriptorsMap[identity] = descriptor
    }

    //pre-process consensus by filering the routers that do not obey
    //the minimal constraints
    console.log(consensus['routers'].length)
    console.log(descriptors.length)
    lnn.path["consensus"] = consensus['routers'].filter(r => lnn.path.obeyMinimalConstraints(r))
    console.log(lnn.path["consensus"].length)

    //lnn.path selection
    lnn.path["guard"] = guard
    lnn.path["exit"] = lnn.path.chooseGoodExitGivenGuard(tcp_ports)
    lnn.path["middle"] = lnn.path.chooseGoodMiddle()

    //TODO: it should create/return a new lnn.path and not the descriptors
    return [lnn.path.middle, lnn.path.exit]
}

/**
 * This function checks if the given router obeys the minimal constraints needed for a router to be selected
 * 
 * @param {Object} router the router subpart of one of the nodes of the parsed consensus
 */
lnn.path.obeyMinimalConstraints = function (router) {
    let des = lnn.path.descriptorsMap[router['identity']]
    let flags = router['flags']
    
    if(des === undefined) return false
    if (!flags.includes("Valid")) return false
    if (!flags.includes("Running")) return false
    if (!router['version'].startsWith("Tor 0.3.")) return false

    if (des['identity']['type'] !== 'ed25519') return false

    return true
}

/**
 * This function takes candidates and choose one at random weighted by its bandwidth average
 * 
 * @param {Array} candidates the list of candidates
 */

lnn.path.weightedRandomChoice = function (candidates) {
    let total = 0
    
    for(let candidate of candidates){
        let des =lnn.path.descriptorsMap[candidate['identity']]
        if(des !== undefined){
            total += des['bandwidth']['avg']
        }
    }
    
    let r = Math.random() * total
    let upto = 0

    for (let router of candidates) {
        let des = lnn.path.descriptorsMap[router['identity']]

        if(des !== undefined){
            let bandwidth = des['bandwidth']['avg']

            if (upto + bandwidth >= r) return des
            else upto += bandwidth
        }
        
    }

    throw "No candidate has been chosen"
}

/**
 * This function checks if 2 routers are part of the same 16-subnet
 * 
 * @param {Object} des1 the descriptor of the first router
 * @param {Object} des2 the descriptor of the second router
 * 
 */
lnn.path.inSame16Subnet = function (des1, des2) {

    if(lnn.path.isChutney){
        return false
    }

    let addr1 = des1['router']['address'].split(".")
    let addr2 = des2['router']['address'].split(".")

    return addr1[0] === addr2[0] && addr1[1] === addr2[1]
}

/**
 * This function checks if 2 routers are part of the same family
 * 
 * @param {Object} des1 the descriptor of the first router
 * @param {Object} des2 the descriptor of the second router
 */
lnn.path.inSameFamily = function (des1, des2) {
    if (des1['family'] != undefined && des2['family'] != undefined) {
        for (let fam of des1['family']) {
            if (des2['family'].includes(fam)) return true
        }
    }

    return false
}

/**
 * This function choose a good exit given the TOR lnn.path selection rules
 */
lnn.path.chooseGoodExit = function () {
    let candidates = lnn.path.consensus.filter(lnn.path.isGoodExit)
    return lnn.path.weightedRandomChoice(candidates)
}

lnn.path.chooseGoodExitGivenGuard = function (tcp_ports) {
    let candidates = lnn.path.consensus.filter(r => lnn.path.isGoodExitGivenGuard(r,tcp_ports))
    console.log("Exit candidates: " + candidates.length)
    return lnn.path.weightedRandomChoice(candidates)
}

/**
 * This function checks if the given router is a suitable candidate to become an exit
 * 
 * @param {Object} router the router subpart of one of the nodes of the parsed consensus
 */
lnn.path.isGoodExit = function (router) {
    let flags = router['flags']
    if (!flags.includes('Exit') || flags.includes('BadExit')) return false

    if(router['exit-policy'] === undefined ) 
        router['exit-policy'] = lnn.path.descriptorsMap[router.identity]['policy']
    if (router['exit-policy']['type'] !== 'accept') return false

    return true

}

lnn.path.isGoodExitGivenGuard = function (router, tcp_ports) {
    let flags = router['flags']
    if (!flags.includes('Exit') || flags.includes('BadExit')) return false
    let des = lnn.path.descriptorsMap[router.identity]
    

    if(router['exit-policy'] === undefined ) 
        router['exit-policy'] = des['policy']

    let port_arr = router['exit-policy']['PortList']
    for(i = 0; i < tcp_ports.length; i++) {
        let found = false
        let cur_port = tcp_ports[i]

        for(j = 0; j < port_arr.length; j++) {
            if(port_arr[j][0] == cur_port) {
                found = true
                break
            }
            else if(port_arr[j].length == 2){
                if(port_arr[j][0] <= cur_port && cur_port <= port_arr[j][1]) {
                    found = true
                    break
                }
            }
        }

        if(router['exit-policy']['type'] == 'accept') {
            if(!found) return false
        } 
        else {
            if(found) return false
        }
    }

    if(des === undefined){
        return false
    }

    if(des["router"]["identity"] === lnn.path.guard["router"]["identity"]){
        return false
    }

    if (lnn.path.inSame16Subnet(des, lnn.path.guard)) return false
    if (lnn.path.inSameFamily(des, lnn.path.guard)) return false

    return true
}

/**
 * This function choose a good guard given the TOR lnn.path selection rules.
 * 
 * Note:    this implements a lightweight version of the TOR lnn.path selection, where the selection based on the different
 *          sets is put aside
 * 
 */
lnn.path.chooseGoodGuard = function () {
    let candidates = lnn.path.consensus.filter(r => lnn.path.isGoodGuard(r))
    return lnn.path.weightedRandomChoice(candidates)
}

/**
 * This function checks if the given router is a suitable candidate to become a guard
 * 
 * @param {Object} router the router subpart of one of the nodes of the parsed consensus
 */
lnn.path.isGoodGuard = function (router) {
    let flags = router['flags']
    let des = lnn.path.descriptorsMap[router.identity]

    if(des === undefined){
        return false
    }

    if(des["router"]["identity"] === lnn.path.exit["router"]["identity"]){
        return false
    }

    if (!flags.includes('Guard')) return false
    if (!flags.includes('Stable')) return false
    if (!flags.includes('V2Dir')) return false
    if (lnn.path.inSame16Subnet(des, lnn.path.exit)) return false
    if (lnn.path.inSameFamily(des, lnn.path.exit)) return false

    return true
}

/**
 * This function choose a good middle given the TOR lnn.path selection rules
 */
lnn.path.chooseGoodMiddle = function () {
    let candidates = lnn.path.consensus.filter(r => lnn.path.isGoodMiddle(r))
    return lnn.path.weightedRandomChoice(candidates)
}

/**
 * This function checks if the given router is a suitable candidate to become a middle node
 * 
 * @param {Object} router the router subpart of one of the nodes of the parsed consensus
 */
lnn.path.isGoodMiddle = function (router) {
    let des = lnn.path.descriptorsMap[router.identity]

    if(des === undefined){
        return false
    }

    if(des["router"]["identity"] === lnn.path.exit["router"]["identity"] ||des["router"]["identity"] === lnn.path.guard["router"]["identity"]){
        return false
    }

    if (lnn.path.inSame16Subnet(des, lnn.path.guard)) return false
    if (lnn.path.inSame16Subnet(des, lnn.path.exit)) return false
    if (lnn.path.inSameFamily(des, lnn.path.guard)) return false
    if (lnn.path.inSameFamily(des, lnn.path.exit)) return false

    return true
}

