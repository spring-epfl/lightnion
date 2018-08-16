"use strict"

var lighttor = {}
lighttor.api = {}
lighttor.api.url = "/lighttor/api/v0.1"
lighttor.api.version = "0.1"
lighttor.api.ws_port = "8765"

lighttor.state = {
        started: 1,
        guarded: 2,
        created: 3,
        pending: 4,
        extpath: 5,
        success: 6
    }
