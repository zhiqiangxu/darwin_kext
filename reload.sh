sudo rm -rf /tmp/darwin_kext.kext && sudo cp -R /Users/xuzhiqiang/Library/Developer/Xcode/DerivedData/darwin_kext-dddnieomdswxidgnipbvumxihypp/Build/Products/Debug/darwin_kext.kext /tmp/darwin_kext.kext

if kextstat | grep -q "com.qtt.xuzhiqiang.gotproxy"; then
    echo "unloading com.qtt.xuzhiqiang.gotproxy"
    sudo kextunload -b com.qtt.xuzhiqiang.gotproxy
fi
sudo kextload  /tmp/darwin_kext.kext
sudo cp -R /tmp/darwin_kext.kext /Users/xuzhiqiang/.gvm/pkgsets/go1.10/global/src/github.com/zhiqiangxu/gotproxy/darwin/
