class Surface {
    constructor(ptr) {
        if (ptr == 0) {
            throw "NULL pointer";
        }
        this.ptr = ptr;
        this.width =  ptr.add(2 * 4).readU32();
        this.height = ptr.add(3 * 4).readU32();
        this.pitch =  ptr.add(4 * 4).readU16();
        this.pixels = ptr.add(5 * 4).readPointer();
        this.locked = ptr.add(11 * 4).readU32();
        this.bytesPerPixel = Math.trunc(this.pitch/this.width);
        this.bufferSize = this.pitch*this.height;

        // prepare a custom struct for double buffering
        this.customBuffer = Memory.alloc(this.bufferSize);
        this.customStruct = Memory.alloc(15*4);
        Memory.copy(this.customStruct, this.ptr, 15*4);
        this.customStruct.add(5*4).writePointer(this.customBuffer);
    }

    lock() {
        this.ptr.add(11*4).writeU32(++this.locked);
    }

    unlock() {
        this.ptr.add(11*4).writeU32(--this.locked);
    }

    darken() {
        let srcRowLen = this.pitch;
        let bytesPerPixel = this.bytesPerPixel;
        let src = new Uint8Array(this.getOriginalBytes());
        
        for (let j=0; j<this.bufferSize; j+=srcRowLen) {
            for (let i=0; i<srcRowLen; i+=bytesPerPixel) {
                // get the pixel
                if (i%8 == 0) {
                    this.pixels.add(j+i).writeU32(0xff000000);
                }
            };
        };
    }

    scaleNative() {
        Memory.copy(this.customBuffer, this.pixels, this.bufferSize);
        let srcrect = new SDLRect().setAll(0, 0, 800, 600).ptr;
        let dstrect = new SDLRect().setAll(0, 0, 1600, 1200).ptr;
        // send({
        //     hook: "scaleNative",
        //     dstrect: dstrect,
        //     srcrect: srcrect,
        // });
        ss.stretchLinear(
            this.customStruct,
            srcrect,
            this.ptr,
            dstrect,
            );
    }

    scaleJs() {
        let srcRowLen = this.pitch;
        let dstRowLen = 2*this.pitch;
        let bytesPerPixel = this.bytesPerPixel;
        let src = this.pixels;
        let dst = this.customBuffer;
        
        for (let j=0, dj=0; j<this.bufferSize; j+=srcRowLen, dj=j*4) {
            for (let i=0, di=0; i<srcRowLen; i+=bytesPerPixel, di=i*2) {
                // get the pixel
                let byte = this.pixels.readU32(j+i);
                dst.add(dj+di).writeU32(byte);
                dst.add(dj+di+bytesPerPixel).writeU32(byte);
                dst.add(dj+dstRowLen+di).writeU32(byte);
                dst.add(dj+dstRowLen+di+bytesPerPixel).writeU32(byte);
            };
        };
    }

    getScaledBytes() {
        return this.customBuffer.readByteArray(4*this.bufferSize);
    }

    revert() {
        Memory.copy(this.pixels, this.customBuffer, this.bufferSize);
    }

    getOriginalBytes() {
        return this.pixels.readByteArray(this.bufferSize);
    }
};

class VideoDevice {
    constructor() {
        this.currentVideo = ptr(0x004EFD40).readPointer();
        this.wmName = this.currentVideo.add(81*4).readPointer().readAnsiString();
        this.visibleSurface = new Surface(this.currentVideo.add(78*4).readPointer());
        this.screenSurface = new Surface(this.currentVideo.add(76*4).readPointer());
        this.iconifyPtr = this.currentVideo.add(65*4).readPointer();
        this.iconifyFcn = new NativeFunction(this.iconifyPtr, "int", ["pointer"]);
        this.fullscreenPtr = this.currentVideo.add(4*4).readPointer();
        this.fullscreenFcn = new NativeFunction(this.fullscreenPtr, "int", ["pointer", "int"]);
    }

    iconify() {
        this.iconifyFcn(this.currentVideo);
    }
}

class SDLRect {
    constructor (ptr) {

        // create a new struct in memory if ptr==null
        if (!ptr) {
            this.ptr = Memory.alloc(8);
            this.setAll(0, 0, 0, 0);
        } else {
            this.ptr = ptr;
        }
    }

    setAll(x, y, w, h) {
        this.x = x;
        this.y = y;
        this.w = w;
        this.h = h;

        return this;
    }

    get x() {
        return this.ptr.readS16();
    }

    get y() {
        return this.ptr.add(2).readS16();
    }

    get h() {
        return this.ptr.add(4).readU16();
    }

    get w() {
        return this.ptr.add(6).readU16();
    }

    set x(val) {
        this.ptr.writeS16(val);
    }

    set y(val) {
        this.ptr.add(2).writeS16(val);
    }

    set w(val) {
        this.ptr.add(4).writeU16(val);
    }

    set h(val) {
        this.ptr.add(6).writeU16(val);
    }
}

// hook file open to save a player
Interceptor.attach(ptr("0x405BDC"), {
    onEnter: function (args) {
        send({
            fname_buffer: this.context.eax,
            fname: this.context.eax.readAnsiString()
        });
    }
})

Interceptor.attach(ptr(0x0046B6E0), {
    onEnter: function (args) {
        args[0] = ptr(1600);
        args[1] = ptr(1200);
        // add resizable flag
        // args[3] = ptr(0x10);
        send({
            hook_name: "SDL_SetVideoMode",
            width: args[0],
            height: args[1],
            bpp: args[2],
            flags: args[3],
        })
    },
})

// let blitted = false;

// SDL_BlitSurface
// Interceptor.attach(ptr(0x004665C0), {
//     onEnter: function (args) {
//         blitted = true;
//         let vd = new VideoDevice();
//         let src = new Surface(ptr(args[0]));
//         let srcrect = new SDLRect(ptr(args[1]));
//         let dst = new Surface(ptr(args[2]));
//         let dstrect = new SDLRect(ptr(args[3]));
//         src.darken();
//         send({
//             hook_name: "SDL_BlitSurface",
//             src: src,
//             srcrect: srcrect,
//             dst: dst,
//             dstrect: dstrect,
//             visibleSurface: vd.visibleSurface.ptr,
//             screenSurface: vd.screenSurface.ptr,
//         });
//     },
// })

class SoftStretch {
    constructor () {
        this.stretchDll = Module.load("stretch.dll");
        this.softStretch = new NativeFunction(
            this.stretchDll.getExportByName("SDL_SoftStretch"),
            "int",
            ["pointer", "pointer", "pointer", "pointer"],
            "mscdecl"
            );
        this.softStretchLinear = new NativeFunction(
            this.stretchDll.getExportByName("SDL_SoftStretchLinear"),
            "int",
            ["pointer", "pointer", "pointer", "pointer"],
            "mscdecl"
            );
        this.softStretchOld = new NativeFunction(
            ptr(0x004A7DC0),
            "int",
            ["pointer", "pointer", "pointer", "pointer"]
            );
    }

    stretch(src, srcrect, dst, dstrect) {
        let ret = this.softStretch(src, srcrect, dst, dstrect);
        if (ret) {
            send({
                hook: "softStretch",
                retval: ptr(ret).readAnsiString(),
            })
        }
    }

    stretchLinear(src, srcrect, dst, dstrect) {
        let ret = this.softStretchLinear(src, srcrect, dst, dstrect);
        if (ret) {
            send({
                hook: "softStretchLinear",
                retval: ptr(ret).readAnsiString(),
            })
        }
    }

    stretchOld(src, srcrect, dst, dstrect) {
        this.softStretchOld(src, srcrect, dst, dstrect);
    }
}

let ss = new SoftStretch();

// SDL_Flip
Interceptor.attach(ptr(0x0046C810), {
    onEnter: function (args) {
        if (this.vd == undefined)
            this.vd = new VideoDevice();
        this.vd.visibleSurface.scaleNative();
    },
    onLeave: function (ret) {
        // revert otherwise next blits will be problematic
        this.vd.visibleSurface.revert();
    }
});


let eventPtr = null;
Interceptor.attach(ptr(0x00464380), { // calls SDL_WaitEvent
    onEnter: function (args) {
        eventPtr = ptr(args[0]);
    },
    onLeave: function (ret) {
        let type = eventPtr.readU8();
        if (type != 24 && type != 13) {
            // send({
            //     hook: "SDL_WaitEvent",
            //     type: type,
            // }, eventPtr.readByteArray(20))

            if (type == 4) {
                // mouse motion
                let x = eventPtr.add(4).readU16();
                let y = eventPtr.add(6).readU16();
                eventPtr.add(4).writeU16(Math.trunc(x/2));
                eventPtr.add(6).writeU16(Math.trunc(y/2));
                let xrel = eventPtr.add(8).readS16();
                let yrel = eventPtr.add(10).readS16();
                eventPtr.add(8).writeS16(Math.trunc(xrel/2));
                eventPtr.add(10).writeS16(Math.trunc(yrel/2));
            } else if (type == 5 || type == 6) {
                // mouse up/down
                let x = eventPtr.add(4).readU16();
                let y = eventPtr.add(6).readU16();
                eventPtr.add(4).writeU16(Math.trunc(x/2));
                eventPtr.add(6).writeU16(Math.trunc(y/2));
            }
        }
    }
})

Interceptor.attach(ptr(0x00462160), {
    onEnter: function(args) {
        this.x = ptr(args[0]);
        this.y = ptr(args[1]);
    },
    onLeave: function (ret) {
        let x = this.x.readU32();
        let y = this.y.readU32();
        // send({
        //     hook: "getMouseState",
        //     x: x,
        //     y: y,
        // })
        this.x.writeU32(Math.trunc(x/2));
        this.y.writeU32(Math.trunc(y/2));
    }
})

function getContext() {
    return ptr(ptr(0x004ECCDC).readU32());
}

rpc.exports = {
    checkDisplay() {
        var ctx = getContext();
        send({
            context: ctx,
            fullScreenFlag: ptr(ctx + 852).readU8(),
        })
    },

    setDisplay(flag) {
        var ctx = getContext();
        var setDisplay = new NativeFunction(ptr(0x401a50), "void", ["uint8", "pointer"]);
        var setFullscreen = new NativeFunction(ptr(0x40fc50), "void", ["pointer", "uint8"], "thiscall");

        setDisplay(flag, ctx);
        setFullscreen(ctx, flag);
    },

    iconify() {
        new VideoDevice().iconify();
    },
};