var config = {
        container: "#OrganiseChart1",
        rootOrientation:  'WEST', // NORTH || EAST || WEST || SOUTH
        // levelSeparation: 30,
        siblingSeparation:   20,
        subTeeSeparation:    60,
        scrollbar: "fancy",
        
        connectors: {
            type: 'step'
        },
        node: {
            HTMLclass: 'nodeExample1'
        }
    },
    ceo = {
        text: {
            name: "explorer",
            pid: "1515",
        },
        HTMLid: "ceo"
    },

    cto = {
        parent: ceo,
        text:{
            name: "Chrome",
            pid: "1717",
        },
        stackChildren: true,
        HTMLid: "coo"
    },
    cbo = {
        parent: ceo,
        text:{
            name: "firefox",
            title: "1818",
        },
        HTMLid: "cbo"
    },
    cdo = {
        parent: cto,
        text:{
            name: "malware.exe",
        },
        
        HTMLid: "cdo"
    },
    cio = {
        parent: cbo,
        text:{
            name: "malware.exe",

        },
        HTMLid: "cio"
    },
   

    ALTERNATIVE = [
        config,
        ceo,
        cto,
        cbo,
        cdo,
        cio
    ];