/**
 * @module path
 */

let path = {}

/**
 * This function selects a path from the parsed consensus and parsed descriptors
 * Flavor is 'unflavored'
 * 
 * @param {Object} consensus a parsed consensus
 * @param {Object} descriptors parsed descriptors of the routers in the consensus
 * @param {Bool} isChutney boolean used to indicate if the path selection is done with routers from chutney
 */
path.select = function (consensus, descriptors, isChutney) {
    if (isChutney === undefined) {
        path["isChutney"] = false
    } else {
        path["isChutney"] = isChutney
    }

    //build a hashmap of descriptor where the keys are the identity
    path["descriptorsMap"] = {}

    for (let descriptor of descriptors) {
        let identity = descriptor['router'].identity
        path.descriptorsMap[identity] = descriptor
    }

    //pre-process consensus by filering the routers that do not obey
    //the minimal constraints
    path["consensus"] = consensus['routers'].filter(r => path.obeyMinimalConstraints(r))

    //path selection
    path["exit"] = path.chooseGoodExit(consensus)
    path["guard"] = path.chooseGoodGuard(consensus)
    path["middle"] = path.chooseGoodMiddle(consensus)

    //TODO: it should create/return a new path and not the descriptors
    return [path.guard, path.middle, path.exit]
}

//assumes microdesc flavor.
path.select_end_path = function (consensus, descriptors, guard, isChutney, tcp_ports) {
    if (isChutney === undefined) {
        path["isChutney"] = false
    } else {
        path["isChutney"] = isChutney
    }

    //build a hashmap of descriptor where the keys are the identity
    let consMap = {}
    for (let router of consensus['routers']) {
        consMap[router['micro-digest']] = router
    }

    path["descriptorsMap"] = {}

    for (let descriptor of descriptors) {
        descriptor['router'] = consMap[descriptor['micro-digest']]
        descriptor['bandwidth'] = {}
        descriptor['bandwidth']['avg'] = descriptor['router']['w']['Bandwidth']

        let identity = descriptor['router'].identity
        path.descriptorsMap[identity] = descriptor
    }

    //pre-process consensus by filering the routers that do not obey
    //the minimal constraints
    console.log(consensus['routers'].length)
    console.log(descriptors.length)
    path["consensus"] = consensus['routers'].filter(r => path.obeyMinimalConstraints(r))
    console.log(path["consensus"].length)

    //path selection
    path["guard"] = guard
    path["exit"] = path.chooseGoodExitGivenGuard(tcp_ports)
    path["middle"] = path.chooseGoodMiddle()

    //TODO: it should create/return a new path and not the descriptors
    return [path.middle, path.exit]
}

/**
 * This function checks if the given router obeys the minimal constraints needed for a router to be selected
 * 
 * @param {Object} router the router subpart of one of the nodes of the parsed consensus
 */
path.obeyMinimalConstraints = function (router) {
    let des = path.descriptorsMap[router['identity']]
    let flags = router['flags']

    if (des === undefined) return false
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

path.weightedRandomChoice = function (candidates) {
    let total = 0

    for (let candidate of candidates) {
        let des = path.descriptorsMap[candidate['identity']]
        if (des !== undefined) {
            total += des['bandwidth']['avg']
        }
    }

    let r = Math.random() * total
    let upto = 0

    for (let router of candidates) {
        let des = path.descriptorsMap[router['identity']]

        if (des !== undefined) {
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
path.inSame16Subnet = function (des1, des2) {

    if (path.isChutney) {
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
path.inSameFamily = function (des1, des2) {
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
path.chooseGoodExit = function () {
    let candidates = path.consensus.filter(path.isGoodExit)
    return path.weightedRandomChoice(candidates)
}

path.chooseGoodExitGivenGuard = function (tcp_ports) {
    let candidates = path.consensus.filter(r => path.isGoodExitGivenGuard(r, tcp_ports))
    console.log("Exit candidates: " + candidates.length)
    return path.weightedRandomChoice(candidates)
}

/**
 * This function checks if the given router is a suitable candidate to become an exit
 * 
 * @param {Object} router the router subpart of one of the nodes of the parsed consensus
 */
path.isGoodExit = function (router) {
    let flags = router['flags']
    if (!flags.includes('Exit') || flags.includes('BadExit')) return false

    if (router['exit-policy'] === undefined)
        router['exit-policy'] = path.descriptorsMap[router.identity]['policy']
    if (router['exit-policy']['type'] !== 'accept') return false

    return true

}

path.isGoodExitGivenGuard = function (router, tcp_ports) {
    let flags = router['flags']
    if (!flags.includes('Exit') || flags.includes('BadExit')) return false
    let des = path.descriptorsMap[router.identity]


    if (router['exit-policy'] === undefined)
        router['exit-policy'] = des['policy']

    let port_arr = router['exit-policy']['PortList']
    for (let i = 0; i < tcp_ports.length; i++) {
        let found = false
        let cur_port = tcp_ports[i]

        for (let j = 0; j < port_arr.length; j++) {
            if (port_arr[j][0] == cur_port) {
                found = true
                break
            }
            else if (port_arr[j].length == 2) {
                if (port_arr[j][0] <= cur_port && cur_port <= port_arr[j][1]) {
                    found = true
                    break
                }
            }
        }

        if (router['exit-policy']['type'] == 'accept') {
            if (!found) return false
        }
        else {
            if (found) return false
        }
    }

    if (des === undefined) {
        return false
    }

    if (des["router"]["identity"] === path.guard["router"]["identity"]) {
        return false
    }

    if (path.inSame16Subnet(des, path.guard)) return false
    if (path.inSameFamily(des, path.guard)) return false

    return true
}

/**
 * This function choose a good guard given the TOR path selection rules.
 * 
 * Note:    this implements a lightweight version of the TOR path selection, where the selection based on the different
 *          sets is put aside
 * 
 */
path.chooseGoodGuard = function () {
    let candidates = path.consensus.filter(r => path.isGoodGuard(r))
    return path.weightedRandomChoice(candidates)
}

/**
 * This function checks if the given router is a suitable candidate to become a guard
 * 
 * @param {Object} router the router subpart of one of the nodes of the parsed consensus
 */
path.isGoodGuard = function (router) {
    let flags = router['flags']
    let des = path.descriptorsMap[router.identity]

    if (des === undefined) {
        return false
    }

    if (des["router"]["identity"] === path.exit["router"]["identity"]) {
        return false
    }

    if (!flags.includes('Guard')) return false
    if (!flags.includes('Stable')) return false
    if (!flags.includes('V2Dir')) return false
    if (path.inSame16Subnet(des, path.exit)) return false
    if (path.inSameFamily(des, path.exit)) return false

    return true
}

/**
 * This function choose a good middle given the TOR path selection rules
 */
path.chooseGoodMiddle = function () {
    let candidates = path.consensus.filter(r => path.isGoodMiddle(r))
    return path.weightedRandomChoice(candidates)
}

/**
 * This function checks if the given router is a suitable candidate to become a middle node
 * 
 * @param {Object} router the router subpart of one of the nodes of the parsed consensus
 */
path.isGoodMiddle = function (router) {
    let des = path.descriptorsMap[router.identity]

    if (des === undefined) {
        return false
    }

    if (des["router"]["identity"] === path.exit["router"]["identity"] || des["router"]["identity"] === path.guard["router"]["identity"]) {
        return false
    }

    if (path.inSame16Subnet(des, path.guard)) return false
    if (path.inSame16Subnet(des, path.exit)) return false
    if (path.inSameFamily(des, path.guard)) return false
    if (path.inSameFamily(des, path.exit)) return false

    return true
}


export { path };