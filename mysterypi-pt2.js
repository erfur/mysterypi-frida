let mouseClick = function (x, y) {
    let pushEvent = new NativeFunction(ptr(0x004643C0), "int", ["pointer"]);
    let buffer = Memory.alloc(8);

    // button down
    buffer.writeU8(5);
    buffer.add(1).writeU8(0);
    buffer.add(2).writeU8(1);
    buffer.add(3).writeU8(1);
    buffer.add(4).writeS16(x);
    buffer.add(6).writeS16(y);
    if (pushEvent(buffer) == -1) {
        send("pushevent error!")
    }

    // button up
    buffer.writeU8(6);
    buffer.add(1).writeU8(0);
    buffer.add(2).writeU8(1);
    buffer.add(3).writeU8(0);
    buffer.add(4).writeS16(x);
    buffer.add(6).writeS16(y);
    if (pushEvent(buffer) == -1) {
        send("pushevent error!")
    }
}

// setInterval(() => {mouseClick(400, 300)}, 1000);

let free = new NativeFunction(ptr(0x004BC4C2), "void", ["pointer"], "mscdecl");
let hint = null;

class Hint {
    // class enum ??
    constructor (addr) {
        if (addr == 0) {
            return null;
        }
        this.addr = addr;
        this.fcnTable = addr.readPointer();
    }

    get onCooldown () {
        return this.addr.add(224).readU8();
    }

    get currTime () {
        return this.addr.add(228).readFloat();
    }

    set currTime (val) {
        this.addr.add(228).writeFloat(val);
    }

    get animObject () {
        return this.addr.add(124).readPointer();
    }

    // access through the function
    get activeSetInfo () {
        let fcn = new NativeFunction(ptr(0x00420260), 
            "pointer", 
            ["pointer", "pointer"], 
            "thiscall"
            );
        let buf = Memory.alloc(12);
        let _info = fcn(this.addr.add(216).readPointer().add(100).readPointer(), buf);

        // data to return
        let objects = new Array();
        
        // push active objects
        let objBufPtr = buf.readPointer();
        let objCount = buf.add(4).readU32();
        if (objBufPtr != ptr(0)) {
            for (let i=0; i<objCount; i++) {
                objects.push(new Set(objBufPtr.add(i*4).readPointer()));
            }
        }

        // free the buffer inside our buffer
        if (buf.readU32()) {
            free(buf.readPointer());
        };

        return objects;
    }

    // direct access through pointers
    getActiveSet(offset) {
        return this.addr.add(216).readPointer()
            .add(100).readPointer()
            .add(26*4).readPointer()
            .add(offset*4).readPointer();
    }
}

Interceptor.attach(ptr(0x0041EB70), {
    onLeave: function (ret) {
        send({
            hook: "HintClass",
            addr: ptr(ret),
        })
        if (!hint) {
            hint = new Hint(ptr(ret));
        }
    }
})

// let toFloat = function (val) {
//     let m = Memory.alloc(4);
//     m.writePointer(val);
//     return m.readFloat();
// }

// Interceptor.attach(ptr(0x0041EC40), {
//     onEnter: function (args) {
//         send({
//             hook: "updateHintTimer",
//             this: this.context.ecx,
//             increment: toFloat(args[0]),
//         })
//     }
// })

// Interceptor.attach(ptr(0x0041ECD0), {
//     onEnter: function (args) {
//         send({
//             hook: "updateHintButton",
//             this: this.context.ecx,
//             val: args[0],
//         })
//     }
// })

// modify point popup strings
// Interceptor.attach(ptr(0x00424A80), {
//     onEnter: function (args) {
//         this.m = Memory.alloc(0x20);
//         this.m.writeAnsiString("hello world!");
//         args[0] = this.m;
//     }
// })

class Set {
    // class enum 111
    constructor (addr) {
        if (addr == 0) {
            return null;
        }
        this.addr = ptr(addr);
    }

    get infoBuf () {
        let fcn = new NativeFunction(
            ptr(0x004210C0),
            "pointer",
            ["pointer", "pointer"],
            "thiscall"
        );

        let buf = Memory.alloc(0x10);
        fcn(this.addr, buf);
        
        return buf;
    }

    get info () {
        let buf = this.infoBuf;
        return {
            val0: buf.readPointer(),
            val1: buf.add(4).readPointer(),
            val2: buf.add(8).readPointer(),
            imgCount: buf.add(12).readU32(),
        }
    }

    getImage (offset) {
        let offsetBuf = Memory.alloc(4)
        offsetBuf.writeU32(offset);
        let rectBuf = Memory.alloc(0x10);

        let fcn = new NativeFunction(
            ptr(0x0041DF20),
            "pointer",
            ["pointer", "pointer", "pointer"],
            "thiscall"
        );

        return new Image(
            fcn(this.infoBuf, rectBuf, offsetBuf).readPointer().add(16).readPointer()
        );
    }
}

/*
v22 = getActiveSetImage((int)objInfo, (int *)Block, &v33);
image = *(_DWORD *)(*v22 + 16);
v32 = v22[1];
(*(void (__thiscall **)(int, int *, _DWORD))(*(_DWORD *)image + 16))(image, objRect, 0);

.text:0041A868                 call    getActiveSetImage
.text:0041A86D                 mov     ecx, eax
.text:0041A86F                 push    ebx
.text:0041A870                 mov     eax, [ecx]
.text:0041A872                 mov     edx, [ecx+4]
.text:0041A875                 mov     ecx, [eax+10h]
.text:0041A878                 mov     [esp+60h+var_48], edx
.text:0041A87C                 lea     edx, [esp+60h+objRect]
.text:0041A880                 mov     eax, [ecx]
.text:0041A882                 push    edx
.text:0041A883                 call    dword ptr [eax+10h]
*/

class Image {
    // class enum 108
    constructor (addr) {
        if (addr == 0) {
            return null;
        }
        this.addr = ptr(addr);
        this.getRGBA = new NativeFunction(
            ptr(0x0044340E), 
            "uint8", 
            ["pointer", "int", "int", "int"],
            "thiscall"
        );
    }

    get rect () {
        let fcn = new NativeFunction(
            this.addr.readPointer().add(16).readPointer(),
            "void",
            ["pointer", "pointer", "int"],
            "thiscall"
        );

        let buf = Memory.alloc(0x10);
        fcn(this.addr, buf, 0);
        return {
            x: buf.readS32(),
            y: buf.add(4).readS32(),
            w: buf.add(8).readU32(),
            h: buf.add(12).readU32()
        };
    }

    get isInactive () {
        return this.addr.add(144).readU8() == 1;
    }

    checkClick(x, y) {
        // check with the texture at this[17]
        return this.getRGBA(this.addr.add(17*4).readPointer(), x, y, 3)
    }
}

// let counter = 0;
// Interceptor.attach(ptr(0x0042E9F0), {
//     onEnter: function (args) {
//         counter += 1;
//         if (counter%1000 == 0) {
//             send({
//                 _hook: "objectUnderCursor",
//                 this: ptr(this.context.ecx),
//                 arg2: args[0],
//                 arg3: args[1],
//                 arg4: args[2],
//                 arg5: args[3]
//             })
//         }
//     },
//     onLeave: function (ret) {
//         if (ptr(ret) != 0) {
//             send({
//                 _hook: "objectUnderCursor",
//                 retval: ptr(ret),
//                 type: ptr(ret).add(4).readPointer(),
//             })
//         }
//     }
// })

let gameCtx = () => { return ptr(0x004ECCDC).readPointer() };

// only executed when the pause is caused by an out of bounds click
Interceptor.replace(ptr(0x0040E900), new NativeCallback((t) => {
    // send({
    //     hook: "activatePause",
    //     arg: args[0],
    //     this: this.context.ecx,
    // })
    return;
}, "void", ["pointer"], "thiscall"));

// Interceptor.attach(ptr(0x0040E900), {
//     onEnter: function (args) {
//         send({
//             hook: "activatePause",
//             this: this.context.ecx,
//         })
//     }
// })

// Interceptor.attach(ptr(0x0040EAE0), {
//     onEnter: function (args) {
//         send({
//             hook: "deactivatePause",
//             this: this.context.ecx,
//         })
//     }
// })

// Interceptor.attach(ptr(0x0040EC90), {
//     onEnter: function (args) {
//         send({
//             hook: "unkPause",
//             this: this.context.ecx,
//         })
//     }
// })

const nopInstr = function (addr) {
    const instr = Instruction.parse(addr);
    send(`nop patch instruction at ${addr}: ${instr}`);
    Memory.patchCode(addr, instr.size, code => {
        const cw = new X86Writer(code, { pc: addr });
        cw.putNopPadding(instr.size);
    });
};

const fixedJmp = function (addr, target) {
    const instr = Instruction.parse(addr);
    send(`jmp patch instruction at ${addr}: ${instr}`);
    Memory.patchCode(addr, 0x10, code => {
        const cw = new X86Writer(code, { pc: addr });
        cw.putJmpAddress(target);
    });
};

fixedJmp(ptr(0x0042C28D), ptr(0x0042C2C5));
fixedJmp(ptr(0x0042C29D), ptr(0x0042C2C5));
fixedJmp(ptr(0x0042C2A9), ptr(0x0042C2C5));
fixedJmp(ptr(0x0042C2BF), ptr(0x0042C2C5));

// nopInstr(ptr(0x0042C2BF));
// nopInstr(ptr(0x0042C8A2));

function getContext() {
    return ptr(ptr(0x004ECCDC).readU32());
}

rpc.exports = {
    setTime: function (val) {
        hint.currTime = val;
    },

    resetHint: function () {
        hint.currTime = 68;
    },

    getActiveSets: function () {
        send(hint.activeSetInfo.map((x) => {
            let arr = new Array();
            for (let i=0; i<x.info.imgCount; i++) {
                let img = x.getImage(i);
                if (!img.isInactive)
                    arr.push(img.rect);
            }
            return arr;
        }));
    },

    click: function (x, y) {
        mouseClick(x, y);
    },

    solve: function () {
        let imgArrays = hint.activeSetInfo.map((x) => {
            let arr = new Array();
            for (let i=0; i<x.info.imgCount; i++) {
                arr.push(x.getImage(i));
            }
            return arr;
        })
        
        if (imgArrays.length > 1)
                imgArrays.splice(0, 1);
        
        imgArrays.map((arr) => {
            arr.map((img) => {
                let rect = img.rect;
                let imgX = Math.floor(rect.w/2);
                let imgY = Math.floor(rect.h/2);
                while (img.checkClick(imgX, imgY) == 0) {
                    imgX = Math.floor(Math.random() * rect.w);
                    imgY = Math.floor(Math.random() * rect.h);
                }

                let clickX = rect.x + imgX;
                let clickY = rect.y + imgY;

                if (clickX < 160) clickX = 160;
                if (clickX > 799) clickX = 799;
                if (clickY < 0)   clickY = 0;
                if (clickY > 599) clickY = 599;

                if (!img.isInactive) {
                    mouseClick(rect.x + imgX, rect.y + imgY);
                }
            })
        })
    },

    solveAll: function () {
        let interval = setInterval(() => {
            let setInfo = hint.activeSetInfo;
            
            if (setInfo.length == 0) {
                send("solveAll done.");
                clearInterval(interval);
                return;
            }
            
            let imgArrays = setInfo.map((x) => {
                let arr = new Array();
                for (let i=0; i<x.info.imgCount; i++) {
                    let img = x.getImage(i);
                    if (!img.isInactive)
                        arr.push(img);
                }
                return arr;
            }).filter((a) => {
                return a.length > 0;
            });

            if (imgArrays.length > 1)
                imgArrays.splice(0, 1);
            
            for (let arr of imgArrays) {
                for (let img of arr) {
                    let rect = img.rect;
                    let imgX = Math.floor(rect.w/2);
                    let imgY = Math.floor(rect.h/2);
                    while (img.checkClick(imgX, imgY) == 0) {
                        imgX = Math.floor(Math.random() * rect.w);
                        imgY = Math.floor(Math.random() * rect.h);
                    }

                    let clickX = rect.x + imgX;
                    let clickY = rect.y + imgY;

                    if (clickX < 160) clickX = 160;
                    if (clickX > 799) clickX = 799;
                    if (clickY < 0)   clickY = 0;
                    if (clickY > 599) clickY = 599;

                    if (!img.isInactive) {
                        mouseClick(clickX, clickY);
                        return;
                    }
                }
            }
        }, 400);
    },
};
