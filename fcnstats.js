class FunctionStats {
    constructor () {
        // this.followList = new Array();
        this.data = new Array();
        // this.dataMerged = new Object();
        this.mainThread = Process.enumerateThreads()[0];
    }

    // addFcn(addr) {
    //     this.followList.push(addr);
    // }

    // rmFcn(addr) {
    //     while (this.followList.indexOf(addr) != -1)
    //         this.followList.splice(this.followList.indexOf(addr), 1);
    // }

    excludeRanges () {
        Process.enumerateRanges('--x').map((x) => {
            if (x.file.path.indexOf("MysteryPI.exe") == -1)
                Stalker.exclude({
                    base: x.base,
                    size: x.size,
                })
        });
    }

    mergeSummary () {
        let dataMerged = new Object();
        for (let i=0; i<this.data.length; i++) {
            for (const [fcn, cnt] of Object.entries(this.data[i])) {
                let moduleName = Process.findModuleByAddress(parseInt(fcn, 16)).name;
                if (moduleName == "MysteryPI.exe") {
                    if (dataMerged[fcn])
                        dataMerged[fcn].count += cnt;
                    else
                        dataMerged[fcn] = {
                            count: cnt,
                            range: moduleName,
                        }
                }
            }
        }

        let compareFcn = (a, b) => {
            return a[1].count - b[1].count;
        };

        return Object.entries(dataMerged).sort(compareFcn);
    }

    addSummary(summary) {
        this.data.push(summary);
    }

    activate() {
        this.data = new Array();

        let summaryCallback = (summary) => {
            this.data.push(summary);
        };

        Stalker.follow(this.mainThread.id, {
            events: {
                call: true,
              },
            
              onCallSummary: summaryCallback,
        })
    }

    activateTimed(delay, interval) {
        setTimeout(() => {
            send("initiating stalker.");
            this.activate();

            setTimeout(() => {
                send("stopping stalker.");
                this.deactivate();
            }, interval);
        }, delay)
    }

    deactivate() {
        Stalker.unfollow(this.mainThread.id);
    }

    get lastSummary() {
        return this.data.pop();
    }

    get mergedStat() {
        return this.mergeSummary();
    }

    reset () {
        this.data = new Array();
    }
}

let fs = new FunctionStats();

rpc.exports = {
    stalkinterval (delay, interval) {
        fs.activateTimed(delay*1000, interval*1000);
    },

    stalk() {
        fs.activate();
    },

    unstalk() {
        fs.deactivate();
    },

    stat() {
        send(fs.mergedStat);
    },

    reset() {
        fs.reset();
    }
}
