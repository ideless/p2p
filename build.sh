if [[ -z `which emcc` ]]; then
	source /home/mas/cpp/emsdk/emsdk_env.sh
fi

BUILD_DIR=build
RELEASE_NODE=test
RELEASE_VITE=/home/mas/html/artifact/src/ys/p2p

if [[ -d $BUILD_DIR ]]; then
    rm -rf $BUILD_DIR
fi
mkdir $BUILD_DIR

emcmake cmake -B $BUILD_DIR -D VITE=0
emmake make -C $BUILD_DIR
if [[ ! -d $RELEASE_NODE ]]; then
    mkdir $RELEASE_NODE
fi
cp $BUILD_DIR/p2p.js $BUILD_DIR/p2p.wasm js/p2p.d.ts $RELEASE_NODE

emcmake cmake -B $BUILD_DIR -D VITE=1
emmake make -C $BUILD_DIR
if [[ ! -d $RELEASE_VITE ]]; then
    mkdir $RELEASE_VITE
fi
cp $BUILD_DIR/p2p.js $BUILD_DIR/p2p.wasm js/p2p.d.ts $RELEASE_VITE
