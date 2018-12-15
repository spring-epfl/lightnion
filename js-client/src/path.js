lnn.get.path = {}

/**
 * This function selects a path from the parsed consensus and parsed descriptors
 * 
 * @param {Object} consensus a parsed consensus
 * @param {Object} descriptors parsed descriptors of the routers in the consensus
 * @param {Bool} isChutney boolean used to indicate if the path selection is done with routers from chutney
 */
lnn.get.path.selection = function (consensus, descriptors, isChutney) {

    if(isChutney === undefined){
        lnn.get.path["isChutney"] = false
    }else{
        lnn.get.path["isChutney"] = isChutney
    }

    //build a hashmap of descriptor where the keys are the identity
    lnn.get.path["descriptorsMap"] = {}

    for (let descriptor of descriptors) {
        let identity = descriptor['router'].identity
        lnn.get.path.descriptorsMap[identity] = descriptor
    }

    //pre-process consensus by filering the routers that do not obey
    //the minimal constraints
    lnn.get.path["consensus"] = consensus['routers'].filter(r => !lnn.get.path.obeyMinimalConstraints(r, descriptorsMap))

    //path selection
    lnn.get.path["exit"] = lnn.get.path.chooseGoodExit(consensus, descriptorsMap)
    lnn.get.path["guard"] = lnn.get.path.chooseGoodGuard(consensus, exitDescriptor, descriptorsMap)
    lnn.get.path["middle"] = lnn.get.path.chooseGoodMiddle(consensus, guardDecriptor, exitDescriptor, descriptorsMap)

    //TODO: it should create/return a new path and not the descriptors
    return [lnn.get.path.guard, lnn.get.path.middle, lnn.get.path.exit]
}

/**
 * This function checks if the given router obeys the minimal constraints needed for a router to be selected
 * 
 * @param {Object} router the router subpart of one of the nodes of the parsed consensus
 */
lnn.get.path.obeyMinimalConstraints = function (router) {
    let des = lnn.get.path.descriptorsMap[router['identity']]
    let flags = router['flags']

    if (!flags.includes("Valid")) return false
    if (!flags.includes("Running")) return false
    if (!router['version'].startsWith("TOR 0.3.")) return false
    if (router['digest'] !== des['digest']) return false
    if (des['identity']['type'] !== 'ed25519') return false

    return true
}

/**
 * This function takes candidates and choose one at random weighted by its bandwidth average
 * 
 * @param {Array} candidates the list of candidates
 */
lnn.get.path.weightedRandomChoice = function (candidates) {
    let total = candidates.reduce((acc, r) => acc + lnn.get.path.descriptorsMap[r['identity']]['bandwidth']['avg'], 0)
    let r = Math.random() * total
    let upto = 0

    for (let router of candidates) {
        let des = lnn.get.path.descriptorsMap[router['identity']]
        let bandwidth = des['bandwidth']['avg']

        if (upto + bandwidth >= r) return des
        else upto += bandwidth
    }

    throw "No candidate has been chosen"
}

/**
 * This function checks if 2 routers are part of the same 16-subnet
 * 
 * @param {Object} des1 the descriptor of the first router
 * @param {Object} des2 the descriptor of the second router
 * @param {Bool} isChutney  flag used when the path selection is run with chutney
 *                          (since all router have the same IP address)
 */
lnn.get.path.inSame16Subnet = function (des1, des2, isChutney) {

    if(lnn.get.path.isChutney){
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
lnn.get.path.inSameFamily = function (des1, des2) {
    if (des1['family'] != undefined && des2['family'] != undefined) {
        for (let fam of des1['family']) {
            if (des2['family'].includes(fam)) return true
        }
    }

    return false
}

/**
 * This function choose a good exit given the TOR path selection rules
 */
lnn.get.path.chooseGoodExit = function () {
    let candidates = lnn.get.path.consensus.filter(lnn.get.path.isGoodExit)
    return lnn.get.path.weightedRandomChoice(candidates)
}

/**
 * This function checks if the given router is a suitable candidate to become an exit
 * 
 * @param {Object} router the router subpart of one of the nodes of the parsed consensus
 */
lnn.get.path.isGoodExit = function (router) {
    let flags = router['flags']
    if (!flags.includes('Exit') || flags.includes('BadExit')) return false
    if (router['exit-policy']['type'] !== 'accept') return false

    return true

}

/**
 * This function choose a good guard given the TOR path selection rules.
 * 
 * Note:    this implements a lightweight version of the TOR path selection, where the selection based on the different
 *          sets is put aside
 * 
 */
lnn.get.path.chooseGoodGuard = function () {
    let candidates = lnn.get.path.consensus.filter(r => lnn.get.path.isGoodGuard(r))
    return weightedRandomChoice(candidates)
}

/**
 * This function checks if the given router is a suitable candidate to become a guard
 * 
 * @param {Object} router the router subpart of one of the nodes of the parsed consensus
 */
lnn.get.path.isGoodGuard = function (router) {
    let flags = router['flags']
    let des = lnn.get.path.descriptorsMap[router.identity]

    if (!flags.includes('Guard')) return false
    if (!flags.includes('Stable')) return false
    if (!flags.includes('V2Dir')) return false
    if (lnn.get.path.inSame16Subnet(des, lnn.get.path.exit)) return false
    if (lnn.get.path.inSameFamily(des, lnn.get.path.exit)) return false

    return true
}

/**
 * This function choose a good middle given the TOR path selection rules
 */
lnn.get.path.chooseGoodMiddle = function () {
    let candidates = lnn.get.path.consensus.filter(r => lnn.get.path.isGoodMiddle(r))
    return lnn.get.path.weightedRandomChoice(candidates)
}

/**
 * This function checks if the given router is a suitable candidate to become a middle node
 * 
 * @param {Object} router the router subpart of one of the nodes of the parsed consensus
 */
lnn.get.path.isGoodMiddle = function (router) {
    let des = lnn.get.path.descriptorsMap[router.identity]
    if (lnn.get.path.inSame16Subnet(des, lnn.get.path.guard)) return false
    if (lnn.get.path.inSame16Subnet(des, lnn.get.path.exit)) return false
    if (lnn.get.path.inSameFamily(des, lnn.get.path.guard)) return false
    if (lnn.get.path.inSameFamily(des, lnn.get.path.exit)) return false

    return true
}
